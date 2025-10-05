import sys
from PyQt6.QtWidgets import QApplication
from ui.main_window import AndroidPentestTool


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    window = AndroidPentestTool()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()