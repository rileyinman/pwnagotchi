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
    __description__ = 'Saves GPS coordinates whenever an handshake is captured. The GPS data is get from PAW on android '

    def __init__(self):
        if 'ip' not in self.options or ('ip' in self.options and self.options['ip'] is None):
            self.ip = "192.168.44.1:8080"
        else:
            self.ip = self.options['ip']

    def on_loaded(self):
        logging.info("[paw-gps] Plugin loaded.")
        logging.info(f"[paw-gps] Using IP address {self.ip}.")

    def on_handshake(self, filename):
        gps = requests.get('http://' + self.ip + '/gps.xhtml')
        gps_filename = filename.replace('.pcap', '.paw-gps.json')

        logging.info(f"[paw-gps] Saving GPS to {gps_filename} ({gps}).")
        with open(gps_filename, 'w+t') as f:
            f.write(gps.text)
