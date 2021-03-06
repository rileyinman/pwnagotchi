import logging
import RPi.GPIO as GPIO
import subprocess

import pwnagotchi.plugins as plugins


class GPIOButtons(plugins.Plugin):
    __author__ = 'ratmandu@gmail.com'
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'GPIO Button support plugin'

    def __init__(self):
        self.running = False
        self.ports = {}
        self.commands = None

    def runCommand(self, channel):
        command = self.ports[channel]
        logging.info(f"[gpio_buttons] Button Pressed! Running command: {command}.")
        process = subprocess.Popen(command, shell=True, stdin=None, stdout=open("/dev/null", "w"), stderr=None,
                                   executable="/bin/bash")
        process.wait()

    def on_loaded(self):
        logging.info("[gpio_buttons] Plugin loaded.")

        # get list of GPIOs
        gpios = self.options['gpios']

        # set gpio numbering
        GPIO.setmode(GPIO.BCM)

        for gpio, command in gpios.items():
            gpio = int(gpio)
            self.ports[gpio] = command
            GPIO.setup(gpio, GPIO.IN, GPIO.PUD_UP)
            GPIO.add_event_detect(gpio, GPIO.FALLING, callback=self.runCommand, bouncetime=600)
            logging.info(f"[gpio_buttons] Added command: {command} to GPIO #{gpio}.")
