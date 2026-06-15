import sys
import os
import subprocess
from PyQt6.QtWidgets import QApplication
from ui.main_window import AndroidPentestTool

if os.name == 'nt':
    # Patch subprocess to avoid cmd popups on Windows
    _orig_popen = subprocess.Popen
    def _patched_popen(*args, **kwargs):
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        return _orig_popen(*args, **kwargs)
    subprocess.Popen = _patched_popen


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look
    
    window = AndroidPentestTool()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()