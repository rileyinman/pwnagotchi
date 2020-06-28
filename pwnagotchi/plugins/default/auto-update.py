import glob
import logging
import os
import platform
import re
import shutil
import subprocess
from threading import Lock

import requests

import pwnagotchi
import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile, parse_version as version_to_tuple


def check(version, repo, native=True):
    logging.debug(f"[auto-update] Checking remote version for {repo}, local is {version}.")
    info = {
        'repo': repo,
        'current': version,
        'available': None,
        'url': None,
        'native': native,
        'arch': platform.machine()
    }

    resp = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
    latest = resp.json()
    info['available'] = latest_ver = latest['tag_name'].replace('v', '')
    is_arm = info['arch'].startswith('arm')

    local = version_to_tuple(info['current'])
    remote = version_to_tuple(latest_ver)
    if remote > local:
        if not native:
            info['url'] = f"https://github.com/{repo}/archive/{latest['tag_name']}.zip"
        else:
            # check if this release is compatible with arm6
            for asset in latest['assets']:
                download_url = asset['browser_download_url']
                if download_url.endswith('.zip') and (
                        info['arch'] in download_url or (is_arm and 'armhf' in download_url)):
                    info['url'] = download_url
                    break

    return info


def make_path_for(name):
    path = os.path.join("/tmp/updates/", name)
    if os.path.exists(path):
        logging.debug("[auto-update] Deleting {path}.")
        shutil.rmtree(path, ignore_errors=True, onerror=None)
    os.makedirs(path)
    return path


def download_and_unzip(name, path, display, update):
    target = "%s_%s.zip" % (name, update['available'])
    target_path = os.path.join(path, target)

    logging.info(f"[auto-update] Downloading {update['url']} to {target_path}...")
    display.update(force=True, new_data={'status': f"Downloading {name} {update['available']}..."})

    os.system(f"wget -q '{update['url']}' -O '{target_path}'")

    logging.info(f"[auto-update] Extracting {target_path} to {path}...")
    display.update(force=True, new_data={'status': f"Extracting {name} {update['available']}..."})

    os.system(f"unzip '{target_path}' -d '{path}'")


def verify(name, path, source_path, display, update):
    display.update(force=True, new_data={'status': f"Verifying {name} {name['available']}..."})

    checksums = glob.glob(f"{path}/*.sha256")
    if len(checksums) == 0:
        if update['native']:
            logging.warning("[auto-update] Native update without SHA256 checksum file.")
            return False

    else:
        checksum = checksums[0]

        logging.info(f"[auto-update] Verifying {checksum} for {source_path}...")

        with open(checksum, 'rt') as fp:
            expected = fp.read().split('=')[1].strip().lower()

        real = subprocess.getoutput(f"sha256sum '{source_path}'").split(' ')[0].strip().lower()

        if real != expected:
            logging.warning(f"[auto-update] Checksum mismatch for {source_path}: expected={expected} got={real}.")
            return False

    return True


def install(display, update):
    name = update['repo'].split('/')[1]

    path = make_path_for(name)

    download_and_unzip(name, path, display, update)

    source_path = os.path.join(path, name)
    if not verify(name, path, source_path, display, update):
        return False

    logging.info(f"[auto-update] Installing {name}...")
    display.update(force=True, new_data={'status': f"Installing {name} {update['available']}..."})

    if update['native']:
        dest_path = subprocess.getoutput(f"which {name}")
        if dest_path == "":
            logging.warning(f"[auto-update] Can't find path for {name}.")
            return False

        logging.info(f"[auto-update] Stopping {update['service']}...")
        os.system(f"service {update['service']} stop")
        os.system(f"mv {source_path} {dest_path}")
        logging.info(f"[auto-update] Restarting {update['service']}...")
        os.system(f"service {update['service']} start")
    else:
        if not os.path.exists(source_path):
            source_path = "{source_path}-{update['available']}"

        # setup.py is going to install data files for us
        os.system(f"cd {source_path} && pip3 install .")

    return True


def parse_version(cmd):
    out = subprocess.getoutput(cmd)
    for part in out.split(' '):
        part = part.replace('v', '').strip()
        if re.search(r'^\d+\.\d+\.\d+.*$', part):
            return part
    raise Exception(f'could not parse version from "{cmd}": output=\n{out}')


class AutoUpdate(plugins.Plugin):
    __author__ = 'evilsocket@gmail.com'
    __version__ = '1.1.1'
    __name__ = 'auto-update'
    __license__ = 'GPL3'
    __description__ = 'This plugin checks when updates are available and applies them when internet is available.'

    def __init__(self):
        self.ready = False
        self.status = StatusFile('/root/.auto-update')
        self.lock = Lock()

    def on_loaded(self):
        if 'interval' not in self.options or ('interval' in self.options and not self.options['interval']):
            logging.error("[auto-update] main.plugins.auto-update.interval is not set.")
            return
        self.ready = True
        logging.info("[auto-update] Plugin loaded.")

    def on_internet_available(self, agent):
        if self.lock.locked():
            return

        with self.lock:
            logging.debug(f"[auto-update] Internet connectivity is available (ready {self.ready}).")

            if not self.ready:
                return

            if self.status.newer_then_hours(self.options['interval']):
                logging.debug(f"[auto-update] Last check happened less than {self.options['interval']} hours ago.")
                return

            logging.info("[auto-update] Checking for updates...")

            display = agent.view()
            prev_status = display.get('status')

            try:
                display.update(force=True, new_data={'status': 'Checking for updates...'})

                to_install = []
                to_check = [
                    ('bettercap/bettercap', parse_version('bettercap -version'), True, 'bettercap'),
                    ('evilsocket/pwngrid', parse_version('pwngrid -version'), True, 'pwngrid-peer'),
                    ('evilsocket/pwnagotchi', pwnagotchi.__version__, False, 'pwnagotchi')
                ]

                for repo, local_version, is_native, svc_name in to_check:
                    info = check(local_version, repo, is_native)
                    if info['url'] is not None:
                        logging.warning(f"[auto-update] Update for {repo} available (local version is '{info['current']}'): {info['url']}.")
                        info['service'] = svc_name
                        to_install.append(info)

                num_updates = len(to_install)
                num_installed = 0

                if num_updates > 0:
                    if self.options['install']:
                        for update in to_install:
                            plugins.on('updating')
                            if install(display, update):
                                num_installed += 1
                    else:
                        prev_status = '%d new update%c available!' % (num_updates, 's' if num_updates > 1 else '')

                logging.info("[auto-update] Done.")

                self.status.update()

                if num_installed > 0:
                    display.update(force=True, new_data={'status': 'Rebooting...'})
                    pwnagotchi.reboot()

            except Exception as e:
                logging.error(f"[auto-update] {e}")

            display.update(force=True, new_data={'status': prev_status if prev_status is not None else ''})
