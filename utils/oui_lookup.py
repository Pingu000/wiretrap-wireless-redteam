import requests
import json
import os
import threading

CACHE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "oui_cache.json"
)

def _load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

# Cache cargado una sola vez al importar el módulo; no se relee en
# cada llamada (evita cientos de lecturas de disco durante el escaneo).
_cache = _load_cache()
_pending: set = set()   # prefijos en vuelo para no lanzar duplicados
_lock = threading.Lock()


def _save_cache():
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f)
    except Exception:
        pass


def _fetch_vendor(mac_prefix: str):
    """Consulta la API en segundo plano y actualiza el cache en éxito."""
    try:
        url = f"https://api.macvendors.com/{mac_prefix}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
            with _lock:
                _cache[mac_prefix] = vendor
                _pending.discard(mac_prefix)
            _save_cache()
            return
    except requests.exceptions.RequestException:
        pass
    # En caso de fallo NO escribimos nada en el cache; el próximo
    # arranque volverá a intentarlo cuando haya red disponible.
    with _lock:
        _pending.discard(mac_prefix)


def get_vendor(mac: str) -> str:
    """
    Devuelve el fabricante asociado al prefijo OUI del MAC.
    Retorna inmediatamente: desde cache si ya se conoce, o
    "Desconocido" mientras lanza la consulta en un hilo daemon.
    Nunca bloquea el hilo de captura de paquetes.
    """
    if not mac or len(mac) < 8:
        return "Desconocido"

    mac_prefix = mac.replace(":", "").replace("-", "").upper()[:6]

    with _lock:
        if mac_prefix in _cache:
            return _cache[mac_prefix]
        if mac_prefix not in _pending:
            _pending.add(mac_prefix)
            threading.Thread(
                target=_fetch_vendor,
                args=(mac_prefix,),
                daemon=True
            ).start()

    return "Desconocido"


if __name__ == "__main__":
    test_macs = [
        "00:1A:79:XX:XX:XX",
        "00:16:3E:XX:XX:XX",
        "B8:27:EB:XX:XX:XX",
        "AA:BB:CC:DD:EE:FF",
    ]

    print("Test OUI Lookup:")
    print("-" * 40)
    for mac in test_macs:
        vendor = get_vendor(mac)
        print(f"{mac} → {vendor}")
