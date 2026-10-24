"""Dialogue expect minimal sur la console serie d'une VM UTM."""
import os, re, select, sys, time

ANSI = re.compile(r'\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][B0]|\x1b\][^\x07]*\x07')

class Console:
    def __init__(self, pty="/dev/ttys011"):
        self.fd = os.open(pty, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        self.buf = ""
    def lire(self, sec):
        fin = time.monotonic() + sec
        while time.monotonic() < fin:
            r, _, _ = select.select([self.fd], [], [], 0.2)
            if r:
                try: d = os.read(self.fd, 65536)
                except BlockingIOError: continue
                if d: self.buf += ANSI.sub('', d.decode('utf-8', 'replace'))
        return self.buf
    def attendre(self, motif, sec=25):
        fin = time.monotonic() + sec
        rx = re.compile(motif)
        while time.monotonic() < fin:
            if rx.search(self.buf): return True
            self.lire(0.4)
        return False
    def envoyer(self, texte, fin="\r", lent=True):
        """Ecrit octet par octet : un pty de console sature vite (EAGAIN)."""
        data = (texte + fin).encode()
        for i in range(0, len(data), 1):
            bloc = data[i:i+1]
            for _ in range(200):
                _, w, _ = select.select([], [self.fd], [], 0.2)
                if w:
                    try:
                        os.write(self.fd, bloc); break
                    except BlockingIOError:
                        time.sleep(0.02)
            else:
                raise TimeoutError("console saturee a l'ecriture")
            if lent: time.sleep(0.004)
    def vider(self):
        self.lire(0.6); self.buf = ""
    def propre(self, n=25):
        return [l.strip() for l in self.buf.replace('\r', '\n').split('\n') if l.strip()][-n:]
    def close(self):
        os.close(self.fd)
