import logging
import requests

import pwnagotchi.plugins as plugins

# You need an bluetooth connection to your android phone which is running
# PAW server with the GPS "hack" from Systemik and edited by shaynemk
# GUIDE HERE: https://community.pwnagotchi.ai/t/setting-up-paw-gps-on-android


class PawGPS(plugins.Plugin):
    __author__ = 'leont'
    __version__ = '1.0.0'
    __name__ = 'pawgps'
    __license__ = 'GPL3'
    __description__ = 'Saves GPS coordinates whenever an handshake is captured. The GPS data is fetched from PAW on Android.'

    def __init__(self):
        self.ip = "192.168.44.1:8080"

    def on_loaded(self):
        if 'ip' in self.options:
            self.ip = self.options['ip']

        logging.info("[paw-gps] Plugin loaded.")
        logging.info(f"[paw-gps] Using IP address {self.ip}.")

    def on_handshake(self, agent, filename, access_point, client_station):
        gps = requests.get(f'http://{self.ip}/gps.xhtml')
        gps_filename = filename.replace('.pcap', '.paw-gps.json')

        logging.info(f"[paw-gps] Saving GPS to {gps_filename} ({gps}).")
        with open(gps_filename, 'w+t') as f:
            f.write(gps.text)
