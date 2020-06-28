import logging
import requests
import websockets

from requests.auth import HTTPBasicAuth


def decode(r, verbose_errors=True):
    try:
        return r.json()
    except Exception as e:
        if r.status_code == 200:
            logging.error(f"Error while decoding json: error='{e}' resp='{r.text}'")
        else:
            err = f"error {r.status_code}: {r.text.strip()}"
            if verbose_errors:
                logging.info(err)
            raise Exception(err)
        return r.text


class Client(object):
    def __init__(self, hostname='localhost', scheme='http', port=8081, username='user', password='pass'):
        self.hostname = hostname
        self.scheme = scheme
        self.port = port
        self.username = username
        self.password = password
        self.url = "{scheme}://{hostname}:{port}/api"
        self.websocket = "ws://{username}:{password}@{hostname}:{port}/api"
        self.auth = HTTPBasicAuth(username, password)

    def session(self):
        r = requests.get(f"{self.url}/session", auth=self.auth)
        return decode(r)

    async def start_websocket(self, consumer):
        s = "{self.websocket}/events"
        while True:
            try:
                async with websockets.connect(s, ping_interval=60, ping_timeout=90) as ws:
                    async for msg in ws:
                        try:
                            await consumer(msg)
                        except Exception as ex:
                            logging.debug(f"Error while parsing event ({ex})")
            except websockets.exceptions.ConnectionClosedError:
                logging.debug("Lost websocket connection. Reconnecting...")
            except websockets.exceptions.WebSocketException as wex:
                logging.debug(f"Websocket exception ({wex})")

    def run(self, command, verbose_errors=True):
        r = requests.post(f"{self.url}/session", auth=self.auth, json={'cmd': command})
        return decode(r, verbose_errors=verbose_errors)
