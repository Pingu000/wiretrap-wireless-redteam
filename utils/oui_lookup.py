import requests
import json
import os

# Cache local para no repetir peticiones al mismo fabricante
CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "oui_cache.json"
)

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def get_vendor(mac: str) -> str:
    """
    Dado un MAC address, devuelve el fabricante del dispositivo.
    Usa cache local para no repetir peticiones.
    
    Args:
        mac: MAC address en formato AA:BB:CC:DD:EE:FF
    
    Returns:
        Nombre del fabricante o 'Desconocido'
    """
    if not mac or len(mac) < 8:
        return "Desconocido"

    # Normalizamos el prefijo (primeros 3 bytes)
    mac_prefix = mac.replace(":", "").replace("-", "").upper()[:6]

    # Comprobamos cache primero
    cache = load_cache()
    if mac_prefix in cache:
        return cache[mac_prefix]

    # Consultamos la API
    try:
        url = f"https://api.macvendors.com/{mac_prefix}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
        else:
            vendor = "Desconocido"
    except requests.exceptions.RequestException:
        vendor = "Desconocido"

    # Guardamos en cache
    cache[mac_prefix] = vendor
    save_cache(cache)

    return vendor


if __name__ == "__main__":
    # Test rápido con MACs conocidas
    test_macs = [
        "00:1A:79:XX:XX:XX",  # Apple
        "00:16:3E:XX:XX:XX",  # Xensource (Citrix)
        "B8:27:EB:XX:XX:XX",  # Raspberry Pi
        "AA:BB:CC:DD:EE:FF",  # Desconocido
    ]

    print("Test OUI Lookup:")
    print("-" * 40)
    for mac in test_macs:
        vendor = get_vendor(mac)
        print(f"{mac} → {vendor}")
