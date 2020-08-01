"""
GScanner

description:

author: Haluk Shan
website: halukshan@gmail.com
Last edited: 2020-4-2
"""

import sys
from Module.HostDetect import HostDetectWidget
from Module.PortScan import PortScanWidget
from PyQt5.QtWidgets import *
import os

class TabWidget(QTabWidget):
    def __init__(self, parent=None):
        super(TabWidget, self).__init__(parent)
        self.resize(700, 300)
        self.PortScan = PortScanWidget()
        self.HostDetectWidget = HostDetectWidget()
        self.addTab(self.HostDetectWidget, u"Host Detect")
        self.addTab(self.PortScan, u"Port Scan")


class Example(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        if os.geteuid() != 0:
            QMessageBox.information(self, 'Warning', 'You have no root permission, network scanner cannot be run', QMessageBox.Ok, QMessageBox.Ok)

    def initUI(self):
        grid = QGridLayout()
        self.setLayout(grid)
        t = TabWidget()
        grid.addWidget(t, 0, 0)

        self.resize(800, 400)
        self.center()
        self.setWindowTitle('GScanner')
        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())

