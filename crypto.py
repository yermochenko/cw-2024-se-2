from secrets import randbits
import interface
import os
from random import randint

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode

"""
Encrypts and decrypts all data within this program
"""
KEY_LENGTH = 128
BLOCK_SIZE = 16  # AES block size in bytes
PADDING_CHAR = b'\x00'  # Padding character for PKCS7 padding


def generate_key() -> int:
    return randbits(KEY_LENGTH)

def pad(data: bytes) -> bytes:
    """Pad the data to be a multiple of BLOCK_SIZE."""
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + (PADDING_CHAR * padding_length)


def unpad(data: bytes) -> bytes:
    """Unpad the data."""
    return data.rstrip(PADDING_CHAR)

#encryption algorithm
def encrypt(string, receiver):
    #if there is no key - there is no encryption
    if interface.shared_key is None:
        interface.send_message(string, receiver)
        return string
    else:
        key = bytes.fromhex(hex(interface.shared_key)[2:].zfill(32))  # Convert shared key to bytes
        iv = os.urandom(BLOCK_SIZE)  # Generate a random IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the padded plaintext
        padded_data = pad(string.encode())
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the IV concatenated with ciphertext (for use in decryption)
        interface.send_message(b64encode(iv + ciphertext).decode('utf-8'), receiver)
        return b64encode(iv + ciphertext).decode('utf-8')

#decryption algorithm
def decrypt(string):
    # if there is no key - there is no decryption
    if interface.shared_key is None:
        return string
    else:
        # Decode the base64 encoded data
        data = b64decode(string)
        for el in data:
            print(el, end=" ")
        data_listed = list(data)
        # Extract IV and ciphertext
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
        # Prepare the cipher
        key = bytes.fromhex(hex(interface.shared_key)[2:].zfill(32))  # Convert shared key to bytes
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and unpad the data
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_data = unpad(decrypted_padded_data)
        interface.send_message_to('debug: ' + decrypted_data.decode('utf-8') + '\n data: ' + str(data_listed), 3)
        return decrypted_data.decode('utf-8')

#generating alice's secret and alice's key
def gen_alice(p, g):
    secret = randint(0, 1000)
    key_a = g**secret % p
    interface.send_message_to('Alice: my key is ' + str(key_a), 2)
    interface.send_message_to('Alice: my key is ' + str(key_a), 3)
    interface.send_message_to('(not a message) Alice\'s secret is ' + str(secret) + ' and key will be counted using formula {}**{}%{}'.format(g, secret, p), 1)
    return key_a, secret
#generating bob's secret and bob's key
def gen_bob(p, g):
    secret = randint(0, 1000)
    key_b = g**secret % p
    interface.send_message_to('Bob: my key is ' + str(key_b), 1)
    interface.send_message_to('Bob: my key is ' + str(key_b), 3)
    interface.send_message_to('(not a message) Bob\'s secret is ' + str(secret) + ' and key will be counted using formula {}**{}%{}'.format(g, secret, p), 2)
    return key_b, secret

#creating a shared key and sending messages for debug
def gen_alice_n_bob(p, key_a, key_b, secret_a, secret_b):
    shared_key_a = key_b ** secret_a % p
    shared_key_b = key_a ** secret_b % p
    interface.send_message_to('(not a message) Final key formula {}**{}%{} '
                              'and the result is equal to '.format(key_b, secret_a, p) + str(shared_key_a), 1)
    interface.send_message_to('(not a message) Final key formula {}**{}%{} '
                              'and the result is equal to '.format(key_a, secret_b, p) + str(shared_key_b), 2)
    return shared_key_a



def generate_key_pair(p, g):
    key_a, secret_a  = gen_alice(p, g)
    key_b, secret_b = gen_bob(p, g)
    shared_key = gen_alice_n_bob(p, key_a, key_b, secret_a, secret_b)
    return key_a, key_b, shared_key