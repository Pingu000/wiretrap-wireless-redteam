import os
import sys

# Verificar que se ejecuta como root
if os.geteuid() != 0:
    print("[!] WireTrap requiere privilegios de root.")
    print("    Ejecuta: sudo python3 main.py")
    sys.exit(1)

WIRETRAP_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, WIRETRAP_DIR)

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QIcon
from gui.main_window import WireTrap


def main():
    print("""
 ██╗    ██╗██╗██████╗ ███████╗████████╗██████╗  █████╗ ██████╗ 
 ██║    ██║██║██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
 ██║ █╗ ██║██║██████╔╝█████╗     ██║   ██████╔╝███████║██████╔╝
 ██║███╗██║██║██╔══██╗██╔══╝     ██║   ██╔══██╗██╔══██║██╔═══╝ 
 ╚███╔███╔╝██║██║  ██║███████╗   ██║   ██║  ██║██║  ██║██║     
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
                                                                  
  Wireless Red Team Framework v1.0
  Uso exclusivo en entornos autorizados
    """)

    app = QApplication(sys.argv)
    app.setApplicationName("WireTrap")
    app.setApplicationVersion("1.0")

    window = WireTrap()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
