# WireTrap — Wireless Red Team Framework

Framework modular de auditoría ofensiva WiFi con GUI, desarrollado como proyecto individual
para la asignatura **"Proyectos de Ciberseguridad - Ciberejercicios"** en U-TAD Madrid.

> ⚠️ **Uso exclusivamente académico y autorizado.** Este proyecto cuenta con autorización
> firmada por la universidad, la facultad, el profesor tutor (Eduardo Arriols Núñez) y todos
> los participantes de la demo, realizada en un entorno de laboratorio completamente
> controlado. No usar contra redes o dispositivos sin autorización explícita: el uso de estas
> técnicas sobre redes ajenas sin consentimiento es ilegal.

## Stack técnico

- **OS:** Kali Linux (VirtualBox)
- **Lenguaje:** Python 3
- **GUI:** PyQt6
- **Captura de tráfico:** Scapy
- **AP falso:** hostapd + dnsmasq
- **Post-explotación:** mitmproxy, Scapy
- **Hardware:** Alfa AWUS036ACH v.2 (RTL8812AU, `wlan1`, principal) + Alfa AWUS036ACHM
  (MT7610U, `wlan0mon`, monitor)

## Flujo funcional

1. Escaneo pasivo de APs y clientes en modo monitor (channel hopping 2.4/5 GHz)
2. Motor de decisión automático por perfil de seguridad (OPEN/WEP/WPA/WPA2/WPA3)
3. Deauth en bucle continuo suplantando al AP legítimo
4. Evil Twin con hostapd + dnsmasq + NAT (internet real para el cliente)
5. Post-explotación: captura HTTP en tiempo real, DNS spoofing (pendiente), inyección HTTP (pendiente)
6. Informe PDF automatizado (pendiente)

## Estructura

```
WireTrap/
├── main.py                    # Punto de entrada, verifica root, lanza GUI
├── core/
│   ├── scanner.py              # Escaneo pasivo 802.11, channel hopping
│   ├── deauth.py                # Deauth loop con Scapy
│   ├── evil_twin.py             # hostapd + dnsmasq + NAT
│   └── decision_engine.py       # Motor de decisión por perfil de AP
├── post_exploitation/
│   └── http_capture.py          # Captura credenciales/cookies HTTP
├── reporting/                    # Pendiente: generador PDF
├── gui/
│   └── main_window.py            # GUI PyQt6
└── utils/
    └── oui_lookup.py              # Lookup fabricante por MAC (con cache)
```

## Estado / pendiente

- [x] Fix señal siempre 0 dBm (`_get_signal`)
- [x] Fix detección de dispositivos en modo ahorro (probe requests)
- [ ] DNS spoofing (`post_exploitation/dns_spoof.py`)
- [ ] Generador de informes PDF (`reporting/report_generator.py`)
- [ ] Integración de post-explotación en la GUI
- [ ] Portal cautivo / página clonada

## Ejecución

```bash
sudo python3 main.py
```

Requiere permisos de root para modo monitor, hostapd/dnsmasq e iptables.
