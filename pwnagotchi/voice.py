import random
import gettext
import os


class Voice:
    def __init__(self, lang):
        localedir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'locale')
        translation = gettext.translation(
            'voice', localedir,
            languages=[lang],
            fallback=True,
        )
        translation.install()
        self._ = translation.gettext

    def custom(self, s):
        return s

    def default(self):
        return self._('ZzzzZZzzzzZzzz')

    def on_starting(self):
        return random.choice([
            self._('Hi, I\'m Pwnagotchi! Starting...'),
            self._('New day, new hunt, new pwns!'),
            self._('Hack the Planet!')])

    def on_ai_ready(self):
        return random.choice([
            self._('AI ready.'),
            self._('The neural network is ready.')])

    def on_keys_generation(self):
        return random.choice([
            self._('Generating keys, do not turn off...')])

    def on_normal(self):
        return random.choice([
            '',
            '...'])

    def on_free_channel(self, channel):
        return self._(f'Hey, channel {channel} is free! Your AP will say thanks.')

    def on_reading_logs(self, lines_so_far=0):
        if lines_so_far == 0:
            return self._('Reading last session logs...')
        return self._(f'Read {lines_so_far} log lines so far...')

    def on_bored(self):
        return random.choice([
            self._('I\'m bored...'),
            self._('Let\'s go for a walk!')])

    def on_motivated(self, reward):
        return self._('This is the best day of my life!')

    def on_demotivated(self, reward):
        return self._('Shitty day :/')

    def on_sad(self):
        return random.choice([
            self._('I\'m extremely bored...'),
            self._('I\'m very sad...'),
            self._('I\'m sad'),
            '...'])

    def on_angry(self):
        # passive aggressive or not? :D
        return random.choice([
            '...',
            self._('Leave me alone...'),
            self._('I\'m mad at you!')])

    def on_excited(self):
        return random.choice([
            self._('I\'m living the life!'),
            self._('I pwn therefore I am.'),
            self._('So many networks!!!'),
            self._('I\'m having so much fun!'),
            self._('My crime is that of curiosity...')])

    def on_new_peer(self, peer):
        if peer.first_encounter():
            return random.choice([
                self._(f'Hello {peer.name()}! Nice to meet you.')])
        else:
            return random.choice([
                self._(f'Yo {peer.name()}! Sup?'),
                self._(f'Hey {peer.name()} how are you doing?'),
                self._(f'Unit {peer.name()} is nearby!')])

    def on_lost_peer(self, peer):
        return random.choice([
            self._(f'Uhm... goodbye {peer.name()}'),
            self._(f'{peer.name()} is gone...')])

    def on_miss(self, who):
        return random.choice([
            self._(f'Whoops... {who} is gone.'),
            self._(f'{who} missed!'),
            self._('Missed!')])

    def on_grateful(self):
        return random.choice([
            self._('Good friends are a blessing!'),
            self._('I love my friends!')])

    def on_lonely(self):
        return random.choice([
            self._('Nobody wants to play with me...'),
            self._('I feel so alone...'),
            self._('Where\'s everybody?!')])

    def on_napping(self, secs):
        return random.choice([
            self._(f'Napping for {secs}s...'),
            self._('Zzzzz'),
            self._(f'ZzzZzzz ({secs}s)')])

    def on_shutdown(self):
        return random.choice([
            self._('Good night.'),
            self._('Zzz')])

    def on_awakening(self):
        return random.choice(['...', '!'])

    def on_waiting(self, secs):
        return random.choice([
            self._(f'Waiting for {secs}s...'),
            '...',
            self._(f'Looking around ({secs}s)')])

    def on_assoc(self, ap):
        ssid, bssid = ap['hostname'], ap['mac']
        what = ssid if ssid not in ('', '<hidden>') else bssid
        return random.choice([
            self._(f'Hey {what} let\'s be friends!'),
            self._(f'Associating to {what}'),
            self._(f'Yo {what}!')])

    def on_deauth(self, sta):
        return random.choice([
            self._(f'Just decided that {sta["mac"]} needs no WiFi!'),
            self._(f'Deauthenticating {sta["mac"]}'),
            self._(f'Kickbanning {sta["mac"]}!')])

    def on_handshakes(self, new_shakes):
        s = 's' if new_shakes > 1 else ''
        return self._(f'Cool, we got {new_shakes} new handshake{s}!')

    def on_unread_messages(self, count):
        s = 's' if count > 1 else ''
        return self._(f'You have {count} new message{s}!')

    def on_rebooting(self):
        return self._("Oops, something went wrong... Rebooting...")

    def on_last_session_data(self, last_session):
        status = self._(f'Kicked {last_session.deauthed} stations\n')
        if last_session.associated > 999:
            status += self._('Made >999 new friends\n')
        else:
            status += self._(f'Made {last_session.associated} new friends\n')
        status += self._(f'Got {last_session.handshakes} handshakes\n')
        if last_session.peers == 1:
            status += self._('Met 1 peer')
        elif last_session.peers > 0:
            status += self._(f'Met {last_session.peers} peers')
        return status

    def on_last_session_tweet(self, last_session):
        return self._(
            'I\'ve been pwning for {duration} ({epochs} epochs) and kicked {deauthed} clients! I\'ve also met {associated} new friends and ate {handshakes} handshakes, with an average reward of {reward}!').format(
                duration=last_session.duration_human,
                epochs=last_session.epochs,
                deauthed=last_session.deauthed,
                associated=last_session.associated,
                handshakes=last_session.handshakes,
                reward=last_session.avg_reward)

    def hhmmss(self, count, fmt):
        s = 's' if count > 1 else ''
        if fmt == "h":
            return self._(f"hour{s}")
        if fmt == "m":
            return self._(f"minute{s}")
        if fmt == "s":
            return self._(f"second{s}")
        return fmt
