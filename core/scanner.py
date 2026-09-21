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
    def __init__(self, ssid, bssid, channel, security, signal,
                 pmf_capable=False, pmf_required=False):
        self.ssid = ssid
        self.bssid = bssid
        self.channel = channel
        self.security = security
        self.signal = signal
        self.pmf_capable = pmf_capable
        self.pmf_required = pmf_required
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
        """
        Devuelve (security, pmf_capable, pmf_required).

        Parseo del RSN IE (ID 48) respetando el layout real de bytes:
            version(2) + group_cipher(4) + pairwise_count(2) +
            pairwise_suites(4*n) + akm_count(2) + akm_suites(4*n) +
            rsn_capabilities(2)

        AKM suite byte 4 (OUI 00:0F:AC) = 2 o 6 -> PSK (WPA2-Personal)
        AKM suite byte 4 (OUI 00:0F:AC) = 8      -> SAE (WPA3-Personal)

        RSN capabilities (bits, little-endian):
            bit 7 (0x80) = MFPC -> pmf_capable
            bit 6 (0x40) = MFPR -> pmf_required
        """
        if packet.haslayer(Dot11Beacon):
            cap = packet[Dot11Beacon].cap

            # Recorremos TODOS los IEs sin devolver en el primer match:
            # un AP en modo mixto WPA/WPA2 anuncia el vendor IE legacy
            # (ID 221) Y el RSN IE (ID 48) en la misma trama, y el orden
            # entre ambos no está garantizado. El RSN (WPA2/WPA3 + PMF)
            # tiene prioridad sobre el vendor IE legacy si ambos existen.
            rsn_elt = None
            has_wpa_vendor = False
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48 and rsn_elt is None:
                    rsn_elt = elt.info
                elif elt.ID == 221 and elt.info[:3] == b'\x00\x50\xf2':
                    has_wpa_vendor = True
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break

            if rsn_elt is not None:
                rsn = rsn_elt
                pmf_capable = False
                pmf_required = False
                has_psk = False
                has_sae = False
                try:
                    offset = 2  # version
                    offset += 4  # group cipher suite
                    pairwise_count = int.from_bytes(
                        rsn[offset:offset + 2], 'little'
                    )
                    offset += 2
                    offset += 4 * pairwise_count  # pairwise suites
                    akm_count = int.from_bytes(
                        rsn[offset:offset + 2], 'little'
                    )
                    offset += 2
                    for i in range(akm_count):
                        suite = rsn[offset + 4 * i:offset + 4 * i + 4]
                        if len(suite) < 4:
                            continue
                        akm_type = suite[3]
                        if akm_type in (2, 6):
                            has_psk = True
                        elif akm_type == 8:
                            has_sae = True
                    offset += 4 * akm_count
                    rsn_cap = rsn[offset:offset + 2]
                    if len(rsn_cap) >= 1:
                        pmf_capable = bool(rsn_cap[0] & 0x80)
                        pmf_required = bool(rsn_cap[0] & 0x40)
                except Exception:
                    pass

                if has_sae and has_psk:
                    security = "WPA2/WPA3"
                elif has_sae:
                    security = "WPA3"
                else:
                    security = "WPA2"
                return security, pmf_capable, pmf_required

            if has_wpa_vendor:
                return "WPA", False, False

            if cap & 0x10:
                return "WEP", False, False
            return "OPEN", False, False
        return "DESCONOCIDO", False, False

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
            security, pmf_capable, pmf_required = self._get_security(packet)
            signal = self._get_signal(packet)
            if bssid not in self.aps:
                ap = AccessPoint(ssid, bssid, channel, security, signal,
                                  pmf_capable, pmf_required)
                self.aps[bssid] = ap
                if self.on_ap_found:
                    self.on_ap_found(ap)
            else:
                self.aps[bssid].signal = signal
                self.aps[bssid].pmf_capable = pmf_capable
                self.aps[bssid].pmf_required = pmf_required

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
                client = self.clients[client_mac]
                client.signal = signal
                if client.bssid != ap_bssid:
                    old_bssid = client.bssid
                    if old_bssid in self.aps:
                        self.aps[old_bssid].clients.discard(client_mac)
                    client.bssid = ap_bssid
                    if ap_bssid in self.aps:
                        self.aps[ap_bssid].clients.add(client_mac)

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
