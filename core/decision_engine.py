import os
import sys

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from core.scanner import AccessPoint


# ── Técnicas disponibles ──────────────────────────────────────

class AttackTechnique:
    DEAUTH_EVIL_TWIN   = "deauth_evil_twin"
    DOWNGRADE_ATTACK   = "downgrade_attack"
    CTS_FLOOD          = "cts_flood"
    BEACON_FLOOD       = "beacon_flood"
    NOT_VULNERABLE     = "not_vulnerable"


# ── Resultado del análisis ────────────────────────────────────

class AttackPlan:
    """
    Resultado del motor de decisión para un AP concreto.
    Contiene la técnica recomendada y la explicación del porqué.
    """

    def __init__(self, technique, reason, risk_level, notes=""):
        self.technique   = technique
        self.reason      = reason
        self.risk_level  = risk_level   # "ALTO", "MEDIO", "BAJO"
        self.notes       = notes

    def __repr__(self):
        return (f"AttackPlan(technique={self.technique}, "
                f"risk={self.risk_level}, reason={self.reason})")

    def to_dict(self):
        return {
            "technique":   self.technique,
            "reason":      self.reason,
            "risk_level":  self.risk_level,
            "notes":       self.notes
        }


# ── Motor de decisión ─────────────────────────────────────────

class DecisionEngine:
    """
    Analiza el perfil de un AP y selecciona automáticamente
    la técnica de ataque más adecuada.

    Árbol de decisión:
        OPEN          → Deauth + Evil Twin (sin cifrado, trivial)
        WEP           → Deauth + Evil Twin (cifrado roto)
        WPA           → Deauth + Evil Twin (sin PMF)
        WPA2          → Deauth + Evil Twin (sin PMF por defecto)
        WPA2 + PMF    → Downgrade Attack  (modo transición)
        WPA3          → CTS Flood         (PMF obligatorio)
        DESCONOCIDO   → Beacon Flood      (técnica genérica)
    """

    def analyze(self, ap: AccessPoint) -> AttackPlan:
        """
        Analiza un AP y devuelve el plan de ataque óptimo.

        Args:
            ap: AccessPoint detectado por el scanner

        Returns:
            AttackPlan con la técnica y justificación
        """
        security = ap.security.upper().strip()

        # ── OPEN ─────────────────────────────────────────────
        if security == "OPEN":
            return AttackPlan(
                technique=AttackTechnique.DEAUTH_EVIL_TWIN,
                reason="Red abierta sin cifrado. "
                       "Deauth clásico + Evil Twin trivial.",
                risk_level="ALTO",
                notes="El cliente conectará al Evil Twin "
                      "sin necesidad de credenciales."
            )

        # ── WEP ──────────────────────────────────────────────
        elif security == "WEP":
            return AttackPlan(
                technique=AttackTechnique.DEAUTH_EVIL_TWIN,
                reason="WEP es un cifrado completamente roto. "
                       "Deauth clásico efectivo.",
                risk_level="ALTO",
                notes="WEP puede crackearse en minutos. "
                      "Evil Twin con WEP falso acepta cualquier clave."
            )

        # ── WPA ──────────────────────────────────────────────
        elif security == "WPA":
            return AttackPlan(
                technique=AttackTechnique.DEAUTH_EVIL_TWIN,
                reason="WPA sin PMF. Las tramas de deauth "
                       "no están autenticadas.",
                risk_level="ALTO",
                notes="Captura handshake WPA durante "
                      "la reconexión al Evil Twin."
            )

        # ── WPA2 ─────────────────────────────────────────────
        elif security == "WPA2":
            return AttackPlan(
                technique=AttackTechnique.DEAUTH_EVIL_TWIN,
                reason="WPA2-Personal sin PMF (configuración "
                       "más común en redes domésticas). "
                       "Deauth clásico en bucle continuo.",
                risk_level="ALTO",
                notes="El ~90% de routers domésticos en España "
                      "usan WPA2 sin PMF. Técnica más efectiva "
                      "del proyecto."
            )

        # ── WPA2 + WPA3 (modo transición) ────────────────────
        elif security in ["WPA2/WPA3", "WPA3/WPA2",
                           "PSK+SAE", "SAE+PSK"]:
            return AttackPlan(
                technique=AttackTechnique.DOWNGRADE_ATTACK,
                reason="AP en modo transición WPA2+WPA3. "
                       "Evil Twin que solo anuncia WPA2 fuerza "
                       "al cliente a conectar con el protocolo "
                       "más débil.",
                risk_level="MEDIO",
                notes="El cliente con WPA2 guardado conecta "
                      "automáticamente al Evil Twin WPA2. "
                      "El deauth directo puede fallar si el "
                      "cliente negoció PMF."
            )

        # ── WPA3 ─────────────────────────────────────────────
        elif security == "WPA3":
            return AttackPlan(
                technique=AttackTechnique.CTS_FLOOD,
                reason="WPA3 con PMF obligatorio. El deauth "
                       "clásico no funciona. CTS/RTS flood "
                       "satura el canal a nivel de protocolo "
                       "MAC sin tocar la capa física.",
                risk_level="BAJO",
                notes="El CTS flood degrada la conexión "
                      "existente. La desconexión no es "
                      "inmediata pero es demostrable. "
                      "Explicar esta limitación en la "
                      "memoria suma puntos académicos."
            )

        # ── DESCONOCIDO ───────────────────────────────────────
        else:
            return AttackPlan(
                technique=AttackTechnique.BEACON_FLOOD,
                reason=f"Seguridad '{ap.security}' no "
                       f"identificada con certeza. "
                       f"Beacon flood como técnica genérica "
                       f"de reconocimiento.",
                risk_level="BAJO",
                notes="Inundar el canal con beacons falsos "
                      "puede revelar comportamiento del AP "
                      "y sus clientes."
            )

    def get_technique_description(self, technique) -> str:
        """Devuelve descripción legible de cada técnica"""
        descriptions = {
            AttackTechnique.DEAUTH_EVIL_TWIN: (
                "Deauth en bucle + Evil Twin\n"
                "Desconecta al cliente del AP real y lo fuerza\n"
                "a conectarse al AP falso con el mismo SSID."
            ),
            AttackTechnique.DOWNGRADE_ATTACK: (
                "Downgrade WPA3 → WPA2\n"
                "Evil Twin que solo anuncia WPA2 para forzar\n"
                "al cliente a negociar el protocolo más débil."
            ),
            AttackTechnique.CTS_FLOOD: (
                "CTS/RTS Virtual Jamming\n"
                "Satura el campo NAV del protocolo 802.11\n"
                "para que todos los dispositivos crean que\n"
                "el canal está ocupado."
            ),
            AttackTechnique.BEACON_FLOOD: (
                "Beacon Flood\n"
                "Inunda el canal con cientos de APs falsos\n"
                "saturando los escáneres WiFi del objetivo."
            ),
            AttackTechnique.NOT_VULNERABLE: (
                "No vulnerable\n"
                "El AP tiene configuración de seguridad\n"
                "que resiste las técnicas disponibles."
            ),
        }
        return descriptions.get(technique, "Técnica desconocida")


# ── Test en terminal ──────────────────────────────────────────

if __name__ == "__main__":
    from core.scanner import AccessPoint

    engine = DecisionEngine()

    # Simulamos APs con distintos niveles de seguridad
    test_aps = [
        AccessPoint("RedAbierta",   "AA:BB:CC:DD:EE:01",
                    6,  "OPEN",       -45),
        AccessPoint("RedVieja",     "AA:BB:CC:DD:EE:02",
                    6,  "WEP",        -50),
        AccessPoint("RedCasa",      "AA:BB:CC:DD:EE:03",
                    6,  "WPA2",       -55),
        AccessPoint("RedModerna",   "AA:BB:CC:DD:EE:04",
                    6,  "WPA2/WPA3",  -60),
        AccessPoint("RedSegura",    "AA:BB:CC:DD:EE:05",
                    6,  "WPA3",       -65),
        AccessPoint("RedRara",      "AA:BB:CC:DD:EE:06",
                    6,  "DESCONOCIDO",-70),
    ]

    print("=" * 60)
    print("MOTOR DE DECISIÓN — WireTrap")
    print("=" * 60)

    for ap in test_aps:
        plan = engine.analyze(ap)
        print(f"\nAP: {ap.ssid:<20} Seguridad: {ap.security}")
        print(f"  Técnica:    {plan.technique}")
        print(f"  Riesgo:     {plan.risk_level}")
        print(f"  Razón:      {plan.reason[:60]}...")
        print(f"  Notas:      {plan.notes[:60]}...")
        print("-" * 60)
