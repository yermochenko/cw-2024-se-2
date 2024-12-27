import FreeSimpleGUI as sg
from tensorboard.plugins.core.core_plugin import DEFAULT_PORT

import crypto



"""
Creates GUI for demonstration purposes
"""
#variables
COLUMN_SIZE = (None, 200)
DEFAULT_P = 198
DEFAULT_G = 268
window_alice, window_bob, window_malice, window_info = None, None, None, None

sg.theme('DarkAmber')
i = 'Chat:'
shared_key = None

#opening interface from outside
def open_interface():
    window_logic()

#common layout of a message
def column_layout(i):
    return [[sg.Text(i, size=(50, None))]]
#common layout of a window
def window_layout(title, layout):
    return sg.Window(title, layout, finalize=True, no_titlebar=True, grab_anywhere=True)

################################
# Windows:
def make_win_alice(c_layout):
    layout = [[sg.Text('Alice')],
              [sg.Input(key='-IN-', enable_events=True), sg.Button('Send a message', key='-SEND-')],
              [sg.Column(c_layout, key='-Column-', scrollable=True, vertical_scroll_only = True, expand_y=True, size= COLUMN_SIZE)],
              [sg.Button('Exit')]]
    return window_layout('Alice', layout)


def make_win_bob(c_layout):
    layout = [[sg.Text('Bob')],
              [sg.Input(key='-IN-', enable_events=True), sg.Button('Send a message', key='-SEND-')],
              [sg.Column(c_layout, key='-Column-', scrollable=True, vertical_scroll_only = True, expand_y=True, size= COLUMN_SIZE)],
              [sg.Button('Exit')]]
    return window_layout('Bob', layout)

def make_win_malice(c_layout):
    layout = [[sg.Text('Malary')],
              [sg.Column(c_layout, key='-Column-', scrollable=True, vertical_scroll_only = True, expand_y=True, size= COLUMN_SIZE)],
              [sg.Button('Exit')]]
    return window_layout('Malary', layout)

def make_win_server_info(c_layout):
    layout = [[sg.Column(
              [[sg.Text('Server information and stuffs')],
              [sg.Button('Reopen everything')],
              [sg.Text(' public parameter p = '), sg.Input(default_text=DEFAULT_P, key='p')],
              [sg.Text(' public parameter g = '), sg.Input(default_text=DEFAULT_G, key = 'g')],
              [sg.Text('Secret:')],
              [sg.Text('Alice\'s private key = '), sg.Text(key ='alice_key')],
              [sg.Text('Bob\'s private key ='), sg.Text(key ='bob_key')],
               [sg.Text('Shared secret key ='), sg.Text(key='shared_key')],
              [sg.Button('Generate key')],
              [sg.Button('Exit')]],
               key='-Column-', scrollable=True, vertical_scroll_only = True, expand_y=True, size= COLUMN_SIZE)]]

    return window_layout('Server info', layout)
#############################################
#Sending a message to a window
def send_message(msg, receiver):
    receiver.extend_layout(receiver['-Column-'],column_layout(msg))
    receiver.refresh()
    receiver['-Column-'].contents_changed()

def send_message_to(msg, receiver_index):
    """
    :param msg: string message file
    :param receiver_index : window_alice = 1, window_bob = 2, window_malice = 3, window_info = 4
    :return:
    """
    if receiver_index == 1:
        send_message(msg, window_alice)
    if receiver_index == 2:
        send_message(msg, window_bob)
    if receiver_index == 3:
        send_message(msg, window_malice)
    if receiver_index == 4:
        send_message(msg, window_info)

#logics of windows
def window_logic():


    #initialize
    global window_alice, window_bob, window_malice, window_info
    window_alice, window_bob, window_malice, window_info = make_win_alice(column_layout(i)), make_win_bob(column_layout(i)), make_win_malice(column_layout(i)), make_win_server_info(column_layout(i))

    #change position
    window_alice.move(window_alice.current_location()[0] - 400, window_alice.current_location()[1] - 200)
    window_bob.move(window_alice.current_location()[0] + 100, window_alice.current_location()[1] - 200)
    window_malice.move(window_alice.current_location()[0] + 600, window_alice.current_location()[1] - 200)
    window_info.move(window_alice.current_location()[0] - 350, window_alice.current_location()[1] + 200)
    window_info.set_size((window_info.size[0], window_info.size[1] + 100))

    while True:  # Event Loop
        window, event, values = sg.read_all_windows()
        #go outside if all windows are closed
        if window == sg.WIN_CLOSED:  # if all windows were closed
            break

        #handle closed windows
        if event == sg.WIN_CLOSED or event == 'Exit':
            window.close()
            if window == window_alice:
                window_alice = None
            elif window == window_bob:
                window_bob = None
            elif window == window_malice:
                window_malice = None
            elif window == window_info:  # closing everything
                exit()


        #Reopen other windows
        elif event == 'Reopen everything':
            if not window_alice:
                window_alice = make_win_alice(column_layout(i))
            if not window_bob:
                window_bob = make_win_bob(column_layout(i))
            if not window_malice:
                window_malice = make_win_malice(column_layout(i))
            window_alice.move(100, 100)
            window_bob.move(600, 100)
            window_malice.move(1100, 100)

        #Sending a message
        elif event == '-SEND-':
            window2 = window_bob if window == window_alice else window_alice
            if window_bob and window_malice and window_alice:  # if a valid window, then output to it
                #we encrypt and decrypt the message. sending encrypted version onto website
                sending_message = crypto.decrypt(  crypto.encrypt(str(values['-IN-']), window_malice))
                #Alice and Bob both get messages
                send_message(str('Alice: ' if window == window_alice else 'Bob: ') + sending_message, window2)
                send_message(str('Alice: ' if window == window_alice else 'Bob: ') + sending_message, window)
                window['-IN-'].update('')

        #generating a key
        elif event == 'Generate key':
            global shared_key
            try:
                p = int(values['p'])
                g = int(values['g'])
            except:
                window['p'].update(DEFAULT_P)
                window['g'].update(DEFAULT_G)
                p = DEFAULT_P
                g = DEFAULT_G

            private_key_alice, private_key_bob, shared_key = crypto.generate_key_pair(p, g)
            window['alice_key'].update(private_key_alice)
            window['bob_key'].update(private_key_bob)
            window['shared_key'].update(shared_key)
