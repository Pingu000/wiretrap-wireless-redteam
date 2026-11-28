# WireTrap — Wireless Red Team Framework

Framework modular de auditoría ofensiva WiFi con interfaz gráfica (PyQt6), pensado para
practicar reconocimiento, explotación y post-explotación sobre redes propias o expresamente
autorizadas: desde el escaneo pasivo con recomendación automática de técnica, hasta el
cracking de PMKID/handshakes WPA2, la saturación de APs, un Evil Twin con Internet real para
la víctima y un captive portal de phishing de credenciales con DNS Spoofing dirigido a
dominios concretos.

> ⚠️ Herramienta para uso exclusivo en entornos autorizados (tus propios dispositivos/redes
> o con permiso explícito). El autor no se responsabiliza de ningún uso indebido.

## Tech Stack

- **OS:** Kali Linux
- **Lenguaje:** Python 3
- **GUI:** PyQt6
- **Captura/inyección 802.11:** Scapy
- **AP falso:** hostapd + dnsmasq
- **Saturación de espectro:** mdk4 (Beacon Flood)
- **PMKID / 4-way handshake:** hcxdumptool (PMKID sin clientes), airodump-ng (handshake
  clásico), hcxpcapngtool (conversión a `.hc22000`), hashcat (cracking por diccionario)
- **Servidor del portal cautivo:** Flask
- **Adaptación de plantillas HTML:** BeautifulSoup4
- **Interceptación HTTPS tras login (opcional):** mitmproxy + certificado CA propio
  (`cryptography` / `pyOpenSSL`)
- **Red/firewall:** iptables (NAT + DNAT del portal cautivo, exención post-login)
- **Hardware probado:** Alfa AWUS036ACH v2 (RTL8812AU) en modo AP + Alfa AWUS036ACHM
  (MT7610U) en modo monitor. Las interfaces se eligen desde la GUI, así que cualquier
  adaptador compatible con modo monitor + modo AP debería servir.

### Dependencias Python

```bash
pip3 install PyQt6 scapy flask beautifulsoup4 cryptography pyOpenSSL requests --break-system-packages
```

### Dependencias del sistema (Kali)

```bash
sudo apt install hostapd dnsmasq mdk4 aircrack-ng hcxtools hashcat
# Opcional, solo para la interceptación HTTPS del Captive Portal:
pip3 install mitmproxy --break-system-packages
```

## Módulos

El menú principal da acceso a 4 módulos independientes:

1. **🔒 Criptografía WPA2 (PMKID/Handshakes)** — ataque PMKID sin necesidad de clientes
   conectados (hcxdumptool) o captura de handshake clásica (airodump-ng), conversión a
   `.hc22000` y cracking por diccionario con hashcat.
2. **📡 Beacon Flood** — inunda el entorno con cientos de SSIDs falsos vía mdk4, con opción
   de anunciarlos como redes WPA2 (🔒) para mayor realismo.
3. **💥 Deauth + Evil Twin** — desautenticación continua suplantando al AP legítimo, Evil
   Twin (hostapd + dnsmasq + NAT) con Internet real para la víctima, y sniffer de
   tráfico/credenciales en vivo por cliente conectado (doble clic sobre el cliente abre su
   dashboard).
4. **🎣 Captive Portal** — portal cautivo con plantilla de login (Google o HTML propio),
   sniffer de credenciales por IP víctima (doble clic abre su dashboard), y **DNS Spoofing
   por dominio**: sirve una página propia cuando la víctima visita un dominio concreto,
   manteniendo ese dominio en la barra de direcciones. Por diseño (HSTS + validación de
   certificado) solo es viable contra dominios en **HTTP puro**, no HTTPS real.

El motor de decisión (`core/decision_engine.py`) es un sistema de reglas (sin IA/ML) que,
a partir del perfil de seguridad detectado en el escaneo (OPEN/WEP/WPA/WPA2/WPA3), recomienda
qué técnica aplicar. Dos de las técnicas que puede recomendar (CTS Flood, Downgrade Attack)
son aún teóricas y no tienen módulo de ataque implementado; las que sí están completamente
implementadas son Deauth+Evil Twin y Beacon Flood.

## Project Structure

```
WireTrap/
├── main.py                        # Entry point — comprueba root, lanza la GUI
├── core/
│   ├── scanner.py                 # Escaneo pasivo 802.11, channel hopping, detección de clientes
│   ├── decision_engine.py         # Motor de decisión por reglas según perfil del AP
│   ├── deauth.py                  # Deauth loop vía Scapy
│   ├── evil_twin.py               # hostapd + dnsmasq + NAT (Internet real para la víctima)
│   ├── beacon_flood.py            # Saturación de APs vía mdk4
│   ├── wpa2_crypto.py             # PMKID / handshake / hashcat (hcxdumptool, hcxpcapngtool, hashcat)
│   └── captive_portal.py          # Servidor Flask del portal, plantillas, DNS Spoofing por dominio, MITM opcional
├── post_exploitation/
│   └── sniffer.py                 # Captura HTTP en vivo: credenciales, cookies, DNS, hosts visitados
├── reporting/                     # Pendiente: generador de informe PDF
├── gui/
│   ├── main_window.py             # Ventana principal PyQt6 (los 4 módulos)
│   └── dashboard_dialog.py        # Dashboard de tráfico/credenciales por cliente víctima
├── utils/
│   └── oui_lookup.py              # Resolución de fabricante por MAC (con caché)
└── test_templates/                # Plantillas HTML de prueba para Captive Portal / DNS Spoofing
```

## Status

- [x] Escaneo pasivo con corrección de señal (`_get_signal`) y detección por probe requests
- [x] Motor de decisión por reglas (OPEN/WEP/WPA/WPA2/WPA3)
- [x] Deauth + Evil Twin con Internet real (NAT/iptables)
- [x] Beacon Flood vía mdk4 (con anuncio WPA2 opcional)
- [x] PMKID / Handshake / hashcat pipeline completo
- [x] Captive Portal con plantilla Google o HTML propio
- [x] DNS Spoofing por dominio (plantilla HTML propia por dominio, limitado a HTTP puro)
- [x] Sniffer de credenciales/cookies en vivo, con dashboard por cliente (Evil Twin y Captive Portal)
- [x] Interceptación HTTPS post-login vía mitmproxy + CA propio (opcional)
- [ ] Generador de informe PDF (`reporting/`)
- [ ] CTS Flood / Downgrade Attack (recomendados por el motor de decisión, sin implementar)

## Usage

```bash
sudo python3 main.py
```

Requiere privilegios de root (modo monitor, hostapd/dnsmasq, iptables) y, para el flujo
completo de Evil Twin/Captive Portal, dos interfaces WiFi: una en modo monitor (recon/deauth)
y otra en modo AP (para levantar la red falsa).
