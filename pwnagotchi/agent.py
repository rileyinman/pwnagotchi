import time
import json
import os
import re
import logging
import asyncio
import _thread

import pwnagotchi
import pwnagotchi.utils as utils
import pwnagotchi.plugins as plugins
from pwnagotchi.ui.web.server import Server
from pwnagotchi.automata import Automata
from pwnagotchi.log import LastSession
from pwnagotchi.bettercap import Client
from pwnagotchi.mesh.utils import AsyncAdvertiser
from pwnagotchi.ai.train import AsyncTrainer

RECOVERY_DATA_FILE = '/root/.pwnagotchi-recovery'


class Agent(Client, Automata, AsyncAdvertiser, AsyncTrainer):
    def __init__(self, view, config, keypair):
        Client.__init__(self, config['bettercap']['hostname'],
                        config['bettercap']['scheme'],
                        config['bettercap']['port'],
                        config['bettercap']['username'],
                        config['bettercap']['password'])
        Automata.__init__(self, config, view)
        AsyncAdvertiser.__init__(self, config, view, keypair)
        AsyncTrainer.__init__(self, config)

        self._started_at = time.time()
        self._filter = None if not config['main']['filter'] else re.compile(config['main']['filter'])
        self._current_channel = 0
        self._tot_aps = 0
        self._aps_on_channel = 0
        self._supported_channels = utils.iface_channels(config['main']['iface'])
        self._view = view
        self._view.set_agent(self)
        self._web_ui = Server(self, config['ui'])

        self._access_points = []
        self._last_pwnd = None
        self._history = {}
        self._handshakes = {}
        self.last_session = LastSession(self._config)
        self.mode = 'auto'

        if not os.path.exists(config['bettercap']['handshakes']):
            os.makedirs(config['bettercap']['handshakes'])

        logging.info(f"{pwnagotchi.name()}@{self.fingerprint()} (v{pwnagotchi.__version__})")
        for _, plugin in plugins.loaded.items():
            logging.debug(f"Plugin '{plugin.__class__.__name__}' v{plugin.__version__}")

    def config(self):
        return self._config

    def view(self):
        return self._view

    def supported_channels(self):
        return self._supported_channels

    def setup_events(self):
        logging.info(f"Connecting to {self.url}...")

        for tag in self._config['bettercap']['silence']:
            try:
                self.run(f'events.ignore {tag}', verbose_errors=False)
            except Exception:
                pass

    def _reset_wifi_settings(self):
        mon_iface = self._config['main']['iface']
        self.run(f"set wifi.interface {mon_iface}")
        self.run(f"set wifi.ap.ttl {self._config['personality']['ap_ttl']}")
        self.run(f"set wifi.sta.ttl {self._config['personality']['sta_ttl']}")
        self.run(f"set wifi.rssi.min {self._config['personality']['min_rssi']}")
        self.run(f"set wifi.handshakes.file {self._config['bettercap']['handshakes']}")
        self.run("set wifi.handshakes.aggregate false")

    def start_monitor_mode(self):
        mon_iface = self._config['main']['iface']
        mon_start_cmd = self._config['main']['mon_start_cmd']
        restart = not self._config['main']['no_restart']
        has_mon = False

        while has_mon is False:
            s = self.session()
            for iface in s['interfaces']:
                if iface['name'] == mon_iface:
                    logging.info(f"Found monitor interface: {iface['name']}")
                    has_mon = True
                    break

            if has_mon is False:
                if mon_start_cmd is not None and mon_start_cmd != '':
                    logging.info("Starting monitor interface...")
                    self.run('!%s' % mon_start_cmd)
                else:
                    logging.info(f"Waiting for monitor interface {mon_iface}...")
                    time.sleep(1)

        logging.info(f"Supported channels: {self._supported_channels}")
        logging.info(f"Handshakes will be collected inside {self._config['bettercap']['handshakes']}")

        self._reset_wifi_settings()

        wifi_running = self.is_module_running('wifi')
        if wifi_running and restart:
            logging.debug("Restarting wifi module...")
            self.restart_module('wifi.recon')
            self.run('wifi.clear')
        elif not wifi_running:
            logging.debug("Starting wifi module...")
            self.start_module('wifi.recon')

        self.start_advertising()

    def _wait_bettercap(self):
        while True:
            try:
                _s = self.session()
                return
            except Exception:
                logging.info("Waiting for bettercap API to be available...")
                time.sleep(1)

    def start(self):
        self.start_ai()
        self._wait_bettercap()
        self.setup_events()
        self.set_starting()
        self.start_monitor_mode()
        self.start_event_polling()
        self.start_session_fetcher()
        # print initial stats
        self.next_epoch()
        self.set_ready()

    def recon(self):
        recon_time = self._config['personality']['recon_time']
        max_inactive = self._config['personality']['max_inactive_scale']
        recon_mul = self._config['personality']['recon_inactive_multiplier']
        channels = self._config['personality']['channels']

        if self._epoch.inactive_for >= max_inactive:
            recon_time *= recon_mul

        self._view.set('channel', '*')

        if not channels:
            self._current_channel = 0
            logging.debug(f"RECON {recon_time}s")
            self.run('wifi.recon.channel clear')
        else:
            logging.debug(f"RECON {recon_time}s ON CHANNELS {','.join(map(str, channels))}")
            try:
                self.run(f'wifi.recon.channel {",".join(map(str, channels))}')
            except Exception as e:
                logging.exception(f"Error while setting wifi.recon.channels ({e})")

        self.wait_for(recon_time, sleeping=False)

    def _filter_included(self, ap):
        return self._filter is None or \
               self._filter.match(ap['hostname']) is not None or \
               self._filter.match(ap['mac']) is not None

    def set_access_points(self, aps):
        self._access_points = aps
        plugins.on('wifi_update', self, aps)
        self._epoch.observe(aps, list(self._peers.values()))
        return self._access_points

    def get_access_points(self):
        whitelist = self._config['main']['whitelist']
        aps = []
        try:
            s = self.session()
            plugins.on("unfiltered_ap_list", self, s['wifi']['aps'])
            for ap in s['wifi']['aps']:
                if ap['encryption'] == '' or ap['encryption'] == 'OPEN':
                    continue
                if ap['hostname'] not in whitelist \
                        and ap['mac'].lower() not in whitelist \
                        and ap['mac'][:8].lower() not in whitelist:
                    if self._filter_included(ap):
                        aps.append(ap)
        except Exception as e:
            logging.exception(f"Error while getting acces points ({e})")

        aps.sort(key=lambda ap: ap['channel'])
        return self.set_access_points(aps)

    def get_total_aps(self):
        return self._tot_aps

    def get_aps_on_channel(self):
        return self._aps_on_channel

    def get_current_channel(self):
        return self._current_channel

    def get_access_points_by_channel(self):
        aps = self.get_access_points()
        channels = self._config['personality']['channels']
        grouped = {}

        # group by channel
        for ap in aps:
            ch = ap['channel']
            # if we're sticking to a channel, skip anything
            # which is not on that channel
            if channels and ch not in channels:
                continue

            if ch not in grouped:
                grouped[ch] = [ap]
            else:
                grouped[ch].append(ap)

        # sort by more populated channels
        return sorted(grouped.items(), key=lambda kv: len(kv[1]), reverse=True)

    def _find_ap_sta_in(self, station_mac, ap_mac, session):
        for ap in session['wifi']['aps']:
            if ap['mac'] == ap_mac:
                for sta in ap['clients']:
                    if sta['mac'] == station_mac:
                        return (ap, sta)
                return (ap, {'mac': station_mac, 'vendor': ''})
        return None

    def _update_uptime(self):
        secs = pwnagotchi.uptime()
        self._view.set('uptime', utils.secs_to_hhmmss(secs))
        # self._view.set('epoch', '%04d' % self._epoch.epoch)

    def _update_counters(self):
        self._tot_aps = len(self._access_points)
        tot_stas = sum(len(ap['clients']) for ap in self._access_points)
        if self._current_channel == 0:
            self._view.set('aps', '%d' % self._tot_aps)
            self._view.set('sta', '%d' % tot_stas)
        else:
            self._aps_on_channel = len([ap for ap in self._access_points if ap['channel'] == self._current_channel])
            stas_on_channel = sum(
                [len(ap['clients']) for ap in self._access_points if ap['channel'] == self._current_channel])
            self._view.set('aps', '%d (%d)' % (self._aps_on_channel, self._tot_aps))
            self._view.set('sta', '%d (%d)' % (stas_on_channel, tot_stas))

    def _update_handshakes(self, new_shakes=0):
        if new_shakes > 0:
            self._epoch.track(handshake=True, inc=new_shakes)

        tot = utils.total_unique_handshakes(self._config['bettercap']['handshakes'])
        txt = '%d (%d)' % (len(self._handshakes), tot)

        if self._last_pwnd is not None:
            txt += ' [%s]' % self._last_pwnd[:20]

        self._view.set('shakes', txt)

        if new_shakes > 0:
            self._view.on_handshakes(new_shakes)

    def _update_peers(self):
        self._view.set_closest_peer(self._closest_peer, len(self._peers))

    def _reboot(self):
        self.set_rebooting()
        self._save_recovery_data()
        pwnagotchi.reboot()

    def _save_recovery_data(self):
        logging.warning(f"Writing recovery data to {RECOVERY_DATA_FILE}...")
        with open(RECOVERY_DATA_FILE, 'w') as fp:
            data = {
                'started_at': self._started_at,
                'epoch': self._epoch.epoch,
                'history': self._history,
                'handshakes': self._handshakes,
                'last_pwnd': self._last_pwnd
            }
            json.dump(data, fp)

    def _load_recovery_data(self, delete=True, no_exceptions=True):
        try:
            with open(RECOVERY_DATA_FILE, 'rt') as fp:
                data = json.load(fp)
                logging.info(f"Found recovery data: {data}")
                self._started_at = data['started_at']
                self._epoch.epoch = data['epoch']
                self._handshakes = data['handshakes']
                self._history = data['history']
                self._last_pwnd = data['last_pwnd']

                if delete:
                    logging.info(f"Deleting {RECOVERY_DATA_FILE}")
                    os.unlink(RECOVERY_DATA_FILE)
        except:
            if not no_exceptions:
                raise


    def start_session_fetcher(self):
        _thread.start_new_thread(self._fetch_stats, ())


    def _fetch_stats(self):
        while True:
            s = self.session()
            self._update_uptime()
            self._update_advertisement()
            self._update_peers()
            self._update_counters()
            self._update_handshakes(0)
            time.sleep(1)

    async def _on_event(self, msg):
        found_handshake = False
        jmsg = json.loads(msg)

        if jmsg['tag'] == 'wifi.client.handshake':
            filename = jmsg['data']['file']
            sta_mac = jmsg['data']['station']
            ap_mac = jmsg['data']['ap']
            key = "%s -> %s" % (sta_mac, ap_mac)
            if key not in self._handshakes:
                self._handshakes[key] = jmsg
                s = self.session()
                ap_and_station = self._find_ap_sta_in(sta_mac, ap_mac, s)
                if ap_and_station is None:
                    logging.warning(f"!!! Captured new handshake: {key} !!!")
                    self._last_pwnd = ap_mac
                    plugins.on('handshake', self, filename, ap_mac, sta_mac)
                else:
                    (ap, sta) = ap_and_station
                    self._last_pwnd = ap['hostname'] if ap['hostname'] != '' and ap['hostname'] != '<hidden>' else ap_mac
                    logging.warning(
                        f"!!! Captured new handshake on channel {ap['channel']}, {ap['rssi']} dBm: {sta['mac']} ({sta['vendor']}) -> {ap['hostname']} [{ap['mac']} ({ap['vendor']})] !!!")
                    plugins.on('handshake', self, filename, ap, sta)
                found_handshake = True
            self._update_handshakes(1 if found_handshake else 0)

    def _event_poller(self, loop):
        self._load_recovery_data()
        self.run('events.clear')

        while True:
            logging.debug("Polling events...")
            try:
                loop.create_task(self.start_websocket(self._on_event))
                loop.run_forever()
            except Exception as ex:
                logging.debug(f"Error while polling via websocket ({ex}).")

    def start_event_polling(self):
        # start a thread and pass in the mainloop
        _thread.start_new_thread(self._event_poller, (asyncio.get_event_loop(),))


    def is_module_running(self, module):
        s = self.session()
        for m in s['modules']:
            if m['name'] == module:
                return m['running']
        return False

    def start_module(self, module):
        self.run('%s on' % module)

    def restart_module(self, module):
        self.run('%s off; %s on' % (module, module))

    def _has_handshake(self, bssid):
        for key in self._handshakes:
            if bssid.lower() in key:
                return True
        return False

    def _should_interact(self, who):
        if self._has_handshake(who):
            return False

        if who not in self._history:
            self._history[who] = 1
            return True

        self._history[who] += 1
        return self._history[who] < self._config['personality']['max_interactions']

    def associate(self, ap, throttle=0):
        if self.is_stale():
            logging.debug(f"Recon is stale, skipping assoc({ap['mac']}).")
            return

        if self._config['personality']['associate'] and self._should_interact(ap['mac']):
            self._view.on_assoc(ap)

            try:
                logging.info(f"Sending association frame to {ap['hostname']} ({ap['mac']} {ap['vendor']}) on channel {ap['channel']} [{len(ap['clients'])} clients], {ap['rssi']} dBm...")
                self.run(f"wifi.assoc {ap['mac']}")
                self._epoch.track(assoc=True)
            except Exception as e:
                self._on_error(ap['mac'], e)

            plugins.on('association', self, ap)
            if throttle > 0:
                time.sleep(throttle)
            self._view.on_normal()

    def deauth(self, ap, sta, throttle=0):
        if self.is_stale():
            logging.debug(f"Recon is stale, skipping deauth({sta['mac']}).")
            return

        if self._config['personality']['deauth'] and self._should_interact(sta['mac']):
            self._view.on_deauth(sta)

            try:
                logging.info(f"Deauthing {sta['mac']} ({sta['vendor']}) from {ap['hostname']} ({ap['mac']} {ap['vendor']}) on channel {ap['channel']}, {ap['rssi']} dBm...")
                self.run(f"wifi.deauth {sta['mac']}")
                self._epoch.track(deauth=True)
            except Exception as e:
                self._on_error(sta['mac'], e)

            plugins.on('deauthentication', self, ap, sta)
            if throttle > 0:
                time.sleep(throttle)
            self._view.on_normal()

    def set_channel(self, channel, verbose=True):
        if self.is_stale():
            logging.debug(f"Recon is stale, skipping set_channel({channel}).")
            return

        # if in the previous loop no client stations has been deauthenticated
        # and only association frames have been sent, we don't need to wait
        # very long before switching channel as we don't have to wait for
        # such client stations to reconnect in order to sniff the handshake.
        wait = 0
        if self._epoch.did_deauth:
            wait = self._config['personality']['hop_recon_time']
        elif self._epoch.did_associate:
            wait = self._config['personality']['min_recon_time']

        if channel != self._current_channel:
            if self._current_channel != 0 and wait > 0:
                if verbose:
                    logging.info(f"Waiting for {wait}s on channel {self._current_channel}...")
                else:
                    logging.debug(f"Waiting for {wait}s on channel {self._current_channel}...")
                self.wait_for(wait)
            if verbose and self._epoch.any_activity:
                logging.info(f"CHANNEL {channel}")
            try:
                self.run(f'wifi.recon.channel {channel}')
                self._current_channel = channel
                self._epoch.track(hop=True)
                self._view.set('channel', f'{channel}')

                plugins.on('channel_hop', self, channel)

            except Exception as e:
                logging.error(f"Error while setting channel ({e})")
