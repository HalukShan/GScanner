from scapy.all import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP
from threading import Thread
import queue
from Util import Util, StopThreading


class HostDetectWidget(QDialog):
    def __init__(self):
        super(HostDetectWidget, self).__init__()
        self.taskQueue = queue.Queue()
        self.host_catalog = []
        """ TableWidget """
        self.tableWidget = QTableWidget()
        self.rowcount = 0
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setHorizontalHeaderLabels([' ID  ', 'Host', 'Status'])
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tableWidget.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.tableWidget.verticalHeader().hide()

        """ Start Button """
        self.startbtn = QPushButton('Start', self)
        self.startbtn.resize(self.startbtn.sizeHint())
        self.startbtn.clicked.connect(self.start)

        """ Clear Button """
        self.clearbtn = QPushButton('Clear', self)
        self.clearbtn.resize(self.clearbtn.sizeHint())
        self.clearbtn.clicked.connect(self.clear)

        """ IP Address Input """
        self.hosts = QLineEdit(self)
        self.hosts.setPlaceholderText('e.g. www.xxx.com|192.168.1.101|192.168.1.102-105')
        """ Interface """
        self.interface = QComboBox(self)
        self.add_interface()
        """ Scanner choice """
        self.icmp = QRadioButton('ICMP', self)
        self.arp = QRadioButton('ARP', self)
        self.icmp.setChecked(True)
        self.group = QButtonGroup(self)
        self.group.addButton(self.icmp, 0)
        self.group.addButton(self.arp, 1)

        """ Thread setting """
        self.threadset = QSlider(Qt.Horizontal, self)
        self.threadset.setRange(1, 16)
        self.threadset.valueChanged.connect(self.thread_on_changed)
        self.threadnum = QLabel("1", self)

        """ Process Bar """
        self.pbar = QProgressBar(self)

        """ Status Label """
        self.statusLabel = QLabel("Stop")

        """ Timer"""
        self.timer = QBasicTimer()

        """ Grid """
        grid = QGridLayout()
        self.setLayout(grid)
        grid.addWidget(QLabel("Host"), 0, 0)
        grid.addWidget(self.hosts, 0, 1, 1, 6)
        grid.addWidget(QLabel("Interface", self), 1, 0)
        grid.addWidget(self.interface, 1, 1)
        grid.addWidget(self.icmp, 1, 2)
        grid.addWidget(self.arp, 1, 3)
        grid.addWidget(QLabel("Threads", self), 1, 4)
        grid.addWidget(self.threadset, 1, 5)
        grid.addWidget(self.threadnum, 1, 6)
        grid.addWidget(self.startbtn, 0, 7)
        grid.addWidget(self.tableWidget, 2, 0, 3, 8)
        grid.addWidget(self.clearbtn, 1, 7)
        grid.addWidget(self.pbar, 5, 1, 1, 7)
        grid.addWidget(self.statusLabel, 5, 0)

    def thread_on_changed(self):
        self.threadnum.setText(str(self.threadset.value()))

    def add_interface(self):
        """Get Adapter interface and ip info"""
        self.adapter_info = Util.get_adapter()
        for iface in self.adapter_info.keys():
            self.interface.addItem(iface)

    def clear(self):
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)
        self.statusLabel.setText("Stop")
        self.pbar.setValue(0)

    def add_table_item(self, host):
        row_position = self.tableWidget.rowCount()
        self.tableWidget.insertRow(row_position)
        self.tableWidget.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.tableWidget.setItem(row_position, 1, QTableWidgetItem(host))
        self.tableWidget.setItem(row_position, 2, QTableWidgetItem("Alive"))

    def icmp_scan(self):
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                host = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            ans = sr1(IP(dst=host) / ICMP(), iface=self.interface.currentText(), timeout=0.2, verbose=False)
            if ans:
                self.add_table_item(host)
            self.step = self.step + int(100/self.taskNum)
        self.scan_finished()

    def scan_finished(self):
        if threading.current_thread() in self.threadlist:
            self.threadlist.remove(threading.current_thread())
        if not self.threadlist:
            self.step = 100
            try:
                self.startbtn.clicked.disconnect(self.stop)
            except TypeError:
                pass
            self.startbtn.setText("Start")
            self.startbtn.clicked.connect(self.start)

    def timerEvent(self, e):
        """ Update the process bar """
        self.pbar.setValue(self.step)
        if self.step >= 100:
            self.timer.stop()
            self.statusLabel.setText('Finished')
            return

    def arp_scan(self):
        ip_src, mac_src = self.adapter_info[self.interface.currentText()]
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                ip_dst = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            pkt = Ether()/ARP(op=1, psrc=ip_src, pdst=ip_dst)
            ans = srp1(pkt, iface=self.interface.currentText(), timeout=0.2, verbose=False)
            if ans:
                self.add_table_item(ans['ARP'].psrc + "  " + ans['ARP'].hwsrc)
            self.step = self.step + int(100 / self.taskNum)
        self.scan_finished()

    def start(self):
        if os.geteuid() != 0:
            QMessageBox.information(self, 'Message', 'Root required for Scanner', QMessageBox.Ok, QMessageBox.Ok)
            return
        """ Clear task queue item """
        self.taskQueue.queue.clear()
        hosts_list = Util.get_hosts_list(self.hosts.text())
        if not hosts_list:
            QMessageBox.information(self, 'Message', 'Invalid host!', QMessageBox.Ok, QMessageBox.Ok)
            return
        for host in hosts_list:
            self.taskQueue.put(host)

        """ Reset tasks and start process timer """
        self.taskNum = self.taskQueue.qsize()
        self.step = 0
        self.timer.start(100, self)

        """ Clear row contents and start thread """
        self.clear()
        self.threadlist = []
        if self.group.checkedButton().text() == "ICMP":
            self.threadlist.extend([Thread(target=self.icmp_scan) for _ in range(self.threadset.value())])
        elif self.group.checkedButton().text() == "ARP":
            self.threadlist.extend([Thread(target=self.arp_scan) for _ in range(self.threadset.value())])

        """ Make sure all threads start """
        self.lock = True
        for t in self.threadlist:
            t.start()
        self.lock = False

        """ Set Widget Status """
        self.startbtn.setText("Stop")
        self.startbtn.clicked.disconnect(self.start)
        self.startbtn.clicked.connect(self.stop)
        self.statusLabel.setText("Running...")

    def stop(self):
        self.timer.stop()
        self.statusLabel.setText("Stop")
        for t in self.threadlist:
            StopThreading.stop_thread(t)
        print(self.threadlist)
        self.startbtn.setText("Start")
        try:
            self.startbtn.clicked.disconnect(self.stop)
        except TypeError:
            pass
        self.startbtn.clicked.connect(self.start)
