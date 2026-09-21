import sys
import os

WIRETRAP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WIRETRAP_DIR)

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QTableWidget, QTableWidgetItem, QPushButton,
    QLabel, QComboBox, QHeaderView, QFrame, QSplitter,
    QTextEdit, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QColor, QFont

from core.scanner import Scanner, AccessPoint, Client
from core.deauth import Deauther
from core.evil_twin import EvilTwin
from core.decision_engine import DecisionEngine, AttackTechnique


# ── Bridge para emitir señales desde threads externos ─────────

class SignalBridge(QObject):
    ap_found     = pyqtSignal(object)
    client_found = pyqtSignal(object)
    log_message  = pyqtSignal(str)
    client_joined = pyqtSignal(str)
    attack_stopped = pyqtSignal()


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

        # Módulos core
        self.scanner  = None
        self.deauther = None
        self.evil_twin = None
        self.engine   = DecisionEngine()

        # Bridge de señales
        self.bridge = SignalBridge()
        self.bridge.ap_found.connect(self._on_ap_found)
        self.bridge.client_found.connect(self._on_client_found)
        self.bridge.log_message.connect(self.log)
        self.bridge.client_joined.connect(self._on_client_joined)
        self.bridge.attack_stopped.connect(self._on_attack_stopped)

        self.setup_ui()
        self.apply_styles()
        self._populate_interfaces()

    # ── UI ────────────────────────────────────────────────────

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(8)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Header (barra compacta, no debe competir con las tablas)
        header = QHBoxLayout()
        title = QLabel("🔴 WireTrap v1.0")
        title.setFont(QFont("Monospace", 14, QFont.Weight.Bold))

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

        splitter.setSizes([800, 800])
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

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(110)
        self.log_output.setFont(QFont("Monospace", 9))
        self.log_output.setPlaceholderText(
            "Los eventos aparecerán aquí..."
        )

        attack_layout.addWidget(self.attack_info)
        attack_layout.addWidget(self.log_output)
        attack_group.setMaximumHeight(170)
        main_layout.addWidget(attack_group, 1)

        # Botones
        btn_layout = QHBoxLayout()

        self.btn_scan   = QPushButton("▶  Iniciar Escaneo")
        self.btn_attack = QPushButton("⚡  Iniciar Ataque")
        self.btn_stop   = QPushButton("■  Detener Todo")
        self.btn_report = QPushButton("📄  Generar Informe")

        self.btn_attack.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.btn_report.setEnabled(False)

        self.btn_scan.clicked.connect(self._on_scan_clicked)
        self.btn_attack.clicked.connect(self._on_attack_clicked)
        self.btn_stop.clicked.connect(self._on_stop_clicked)
        self.btn_report.clicked.connect(self._on_report_clicked)

        for btn in [self.btn_scan, self.btn_attack,
                    self.btn_stop, self.btn_report]:
            btn.setFixedHeight(42)
            btn.setFont(QFont("Monospace", 10, QFont.Weight.Bold))
            btn_layout.addWidget(btn)

        main_layout.addLayout(btn_layout)

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

        # Preseleccionar interfaces comunes
        for i, iface in enumerate(interfaces):
            if "wlan0" in iface:
                self.iface_combo.setCurrentIndex(i)
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

        self.attack_info.setText(
            f"Objetivo AP:      {ap_str}\n"
            f"Objetivo Cliente: {client_str}\n"
            f"Técnica:          {tech_str}\n"
            f"Riesgo:           {risk_str}\n"
            f"Estado:           IDLE"
        )

    # ── Callbacks del scanner (desde threads) ─────────────────

    def _on_ap_found(self, ap: AccessPoint):
        """Añade un AP a la tabla — ejecutado en el hilo de la GUI"""
        row = self.ap_table.rowCount()
        self.ap_table.insertRow(row)

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

            # Color por seguridad
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

            self.ap_table.setItem(row, col, item)

    def _on_client_found(self, client: Client):
        """Añade un cliente a la tabla si pertenece al AP seleccionado"""
        if (self.selected_ap and
                client.bssid == self.selected_ap.bssid):
            self._add_client_row(client)

        # Actualizar contador de clientes en la tabla de APs
        for row in range(self.ap_table.rowCount()):
            bssid_item = self.ap_table.item(row, 1)
            if bssid_item and bssid_item.text() == client.bssid:
                ap = self.scanner.aps.get(client.bssid)
                if ap:
                    count_item = QTableWidgetItem(str(len(ap.clients)))
                    count_item.setTextAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )
                    self.ap_table.setItem(row, 5, count_item)
                break

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

    def _on_client_joined(self, info: str):
        self.log(f"[+] Cliente conectado al Evil Twin: {info}")

    def _on_attack_stopped(self):
        self.log("[!] Ataque detenido.")
        self.status_label.setText("● IDLE")
        self.status_label.setStyleSheet(
            "color: gray; font-weight: bold;"
        )
        self.btn_stop.setEnabled(False)
        self.btn_attack.setEnabled(True)
        self.btn_report.setEnabled(True)

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

        # Iniciar evil twin
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
        self.evil_twin.start(
            ssid=self.selected_ap.ssid,
            channel=self.selected_ap.channel or 6,
            security="OPEN",
            out_interface=iface_out
        )

        self.status_label.setText("● ATACANDO")
        self.status_label.setStyleSheet(
            "color: #e94560; font-weight: bold;"
        )
        self.btn_stop.setEnabled(True)
        self.btn_attack.setEnabled(False)

    def _on_stop_clicked(self):
        if self.deauther:
            self.deauther.stop()
        if self.evil_twin:
            self.evil_twin.stop()
        if self.scanner:
            self.scanner.stop()
        self.bridge.attack_stopped.emit()
        self.btn_report.setEnabled(True)

    def _on_report_clicked(self):
        self.log("Generando informe... (próximo paso)")

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
