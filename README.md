# WireTrap — Wireless Red Team Framework

Modular offensive WiFi auditing framework with GUI, developed as a Final Year Project (TFG)
at **U-TAD Madrid** (Software Engineering, Cybersecurity specialization).

> ⚠️ This tool is intended for authorized security testing only. The author is not responsible for any misuse.

## Tech Stack

- **OS:** Kali Linux (VirtualBox)
- **Language:** Python 3
- **GUI:** PyQt6
- **Packet capture:** Scapy
- **Fake AP:** hostapd + dnsmasq
- **Post-exploitation:** Scapy, iptables
- **Hardware:** Alfa AWUS036ACH v.2 (RTL8812AU, `wlan1`, AP mode) + Alfa AWUS036ACHM (MT7610U, `wlan0`, monitor mode)

## Attack Flow

1. Passive scan of APs and clients in monitor mode (channel hopping 2.4/5 GHz)
2. Automatic decision engine based on target security profile (OPEN/WEP/WPA/WPA2/WPA3)
3. Continuous deauthentication loop impersonating the legitimate AP
4. Evil Twin with hostapd + dnsmasq + NAT (real internet for the victim)
5. Captive portal with cloned login page (DNS spoofing + Flask)
6. Post-exploitation: real-time HTTP capture, credential harvesting
7. Automated PDF report (pending)

## Project Structure

```
WireTrap/
├── main.py                        # Entry point — checks root, launches GUI
├── core/
│   ├── scanner.py                 # Passive 802.11 scan, channel hopping
│   ├── deauth.py                  # Deauth loop via Scapy
│   ├── evil_twin.py               # hostapd + dnsmasq + NAT
│   ├── captive_portal.py          # Cloned login page + Flask server + DNS spoof
│   └── decision_engine.py         # Attack decision engine by AP profile
├── post_exploitation/
│   └── http_capture.py            # HTTP credential/cookie capture
├── reporting/                     # Pending: PDF report generator
├── gui/
│   └── main_window.py             # PyQt6 GUI
└── utils/
    └── oui_lookup.py              # MAC vendor lookup (with cache)
```

## Status

- [x] Fix signal always 0 dBm (`_get_signal`)
- [x] Fix device detection via probe requests (power-saving mode)
- [x] Evil Twin with real internet (NAT/iptables)
- [x] Captive portal with page cloning (chromium + monolith)
- [x] DNS spoofing via dnsmasq
- [ ] DNS spoofing hybrid mode (custom domains mid-session)
- [ ] HTTP injection
- [ ] PDF report generator (`reporting/report_generator.py`)
- [ ] Full post-exploitation GUI integration

## Usage

```bash
sudo python3 main.py
```

Requires root for monitor mode, hostapd/dnsmasq, and iptables.
