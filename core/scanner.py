import threading
import time
import os
import sys

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from scapy.all import *
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt,
    Dot11ProbeResp, Dot11AssoReq,
    Dot11ReassoReq, RadioTap
)
from utils.oui_lookup import get_vendor


class AccessPoint:
    def __init__(self, ssid, bssid, channel, security, signal):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.security = security
        self.signal = signal
        self.clients = set()

    def __repr__(self):
        return (f"AP(ssid={self.ssid}, bssid={self.bssid}, "
                f"ch={self.channel}, sec={self.security}, "
                f"signal={self.signal}dBm, clients={len(self.clients)})")


class Client:
    def __init__(self, mac, bssid, signal):
        self.mac = mac
        self.bssid = bssid
        self.signal = signal
        self.vendor = get_vendor(mac)

    def __repr__(self):
        return (f"Client(mac={self.mac}, "
                f"vendor={self.vendor}, "
                f"signal={self.signal}dBm)")


class Scanner:
    def __init__(self, interface):
        self.interface = interface
        self.aps = {}
        self.clients = {}
        self.scanning = False
        self._thread = None
        self._hop_thread = None
        self.on_ap_found = None
        self.on_client_found = None

    def _channel_hopper(self):
        channels = [1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13,
                    36, 40, 44, 48, 52, 56, 60, 64,
                    100, 104, 108, 112, 116, 120, 124, 128,
                    132, 136, 140, 149, 153, 157, 161, 165]
        while self.scanning:
            # Si hay canal fijo, quedarse ahí
            if hasattr(self, 'fixed_channel') and self.fixed_channel:
                try:
                    os.system(
                        f"iw dev {self.interface} set channel "
                        f"{self.fixed_channel} >/dev/null 2>&1"
                    )
                except:
                    pass
                time.sleep(1)
                continue
            # Si no, hacer hopping normal
            for ch in channels:
                if not self.scanning:
                    break
                try:
                    os.system(
                        f"iw dev {self.interface} set channel {ch} "
                        f">/dev/null 2>&1"
                    )
                except:
                    pass
                time.sleep(0.5)

    def _get_signal(self, packet):
        try:
            return packet.dBm_AntSignal
        except:
            return 0

    def _get_security(self, packet):
        if packet.haslayer(Dot11Beacon):
            cap = packet[Dot11Beacon].cap
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:
                    rsn = elt.info
                    if len(rsn) > 6:
                        akm_count = int.from_bytes(rsn[6:8], 'little')
                        if akm_count > 0 and len(rsn) > 10:
                            akm = rsn[10:14]
                            if akm[3] == 8:
                                return "WPA3"
                    return "WPA2"
                if elt.ID == 221 and elt.info[:3] == b'\x00\x50\xf2':
                    return "WPA"
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break
            if cap & 0x10:
                return "WEP"
            return "OPEN"
        return "DESCONOCIDO"

    def _process_packet(self, packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            if not bssid:
                return
            ssid = ""
            try:
                ssid = packet[Dot11Elt].info.decode("utf-8", errors="ignore")
            except:
                ssid = "<hidden>"
            if not ssid:
                ssid = "<hidden>"
            channel = 0
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3:
                    try:
                        channel = ord(elt.info)
                    except:
                        channel = 0
                    break
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break
            security = self._get_security(packet)
            signal = self._get_signal(packet)
            if bssid not in self.aps:
                ap = AccessPoint(ssid, bssid, channel, security, signal)
                self.aps[bssid] = ap
                if self.on_ap_found:
                    self.on_ap_found(ap)
            else:
                self.aps[bssid].signal = signal

        elif packet.haslayer(Dot11) and packet.type == 2:
            ds = packet.FCfield & 0x3
            src = packet[Dot11].addr2
            dst = packet[Dot11].addr1
            bss = packet[Dot11].addr3
            if ds == 1:
                client_mac = src
                ap_bssid = dst
            elif ds == 2:
                client_mac = dst
                ap_bssid = src
            else:
                return
            if not client_mac or client_mac == "ff:ff:ff:ff:ff:ff":
                return
            if int(client_mac.split(":")[0], 16) & 1:
                return
            signal = self._get_signal(packet)
            if client_mac not in self.clients:
                client = Client(client_mac, ap_bssid, signal)
                self.clients[client_mac] = client
                if ap_bssid in self.aps:
                    self.aps[ap_bssid].clients.add(client_mac)
                if self.on_client_found:
                    self.on_client_found(client)
            else:
                self.clients[client_mac].signal = signal

        elif (packet.haslayer(Dot11) and
              packet.type == 0 and
              packet.subtype == 4):
            client_mac = packet[Dot11].addr2
            if not client_mac or client_mac == "ff:ff:ff:ff:ff:ff":
                return
            if int(client_mac.split(":")[0], 16) & 1:
                return
            signal = self._get_signal(packet)
            if client_mac not in self.clients:
                client = Client(client_mac, "probe", signal)
                self.clients[client_mac] = client
                if self.on_client_found:
                    self.on_client_found(client)
            else:
                self.clients[client_mac].signal = signal

    def start(self, fixed_channel=None):
        if self.scanning:
            return
        self.scanning = True
        self.fixed_channel = fixed_channel
        self.aps.clear()
        self.clients.clear()
        self._hop_thread = threading.Thread(
            target=self._channel_hopper,
            daemon=True
        )
        self._hop_thread.start()
        self._thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self._thread.start()

    def _capture_loop(self):
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda p: not self.scanning
        )

    def stop(self):
        self.scanning = False

    def get_clients_for_ap(self, bssid):
        return [
            self.clients[mac]
            for mac in self.aps.get(bssid, AccessPoint("", "", "", "", 0)).clients
            if mac in self.clients
        ]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 scanner.py <interfaz>")
        print("Ejemplo: sudo python3 scanner.py wlan0mon")
        sys.exit(1)

    iface = sys.argv[1]
    scanner = Scanner(iface)

    def ap_callback(ap):
        print(f"[AP]     {ap.ssid:<20} {ap.bssid}  "
              f"ch={ap.channel:<3} {ap.security:<6} {ap.signal}dBm")

    def client_callback(client):
        print(f"[CLIENT] {client.mac}  "
              f"{client.vendor:<25} {client.signal}dBm")

    scanner.on_ap_found = ap_callback
    scanner.on_client_found = client_callback

    print(f"Escaneando en {iface}... (Ctrl+C para parar)\n")
    print(f"{'Tipo':<8} {'SSID/MAC':<20} {'Info'}")
    print("-" * 60)

    try:
        scanner.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        scanner.stop()
        print(f"\n\nResumen final:")
        print(f"  APs detectados:     {len(scanner.aps)}")
        print(f"  Clientes detectados: {len(scanner.clients)}")
