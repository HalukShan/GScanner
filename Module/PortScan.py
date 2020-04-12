from scapy.all import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from scapy.layers.inet import ICMP, IP, TCP, UDP
from threading import Thread
import queue
from Util import Util, StopThreading


class PortScanWidget(QDialog):
    def __init__(self):
        super(PortScanWidget, self).__init__()
        self.taskQueue = queue.Queue()
        self.host_catalog = []
        self.threadlist = []
        """ TableWidget """
        self.tableWidget = QTableWidget()
        self.rowcount = 0
        self.tableWidget.setColumnCount(4)
        self.tableWidget.setHorizontalHeaderLabels([' ID  ', 'Host', 'Port', 'Status'])
        self.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.tableWidget.horizontalHeader().setSectionResizeMode(0, 10)
        self.tableWidget.verticalHeader().hide()

        """ host table """
        self.host_table = QTableWidget()
        self.host_table.setColumnCount(1)
        self.host_table.setHorizontalHeaderLabels(['    Host'])
        self.host_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.host_table.setFixedWidth(60)
        self.host_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.host_table.horizontalHeader().setStretchLastSection(True)
        self.host_table.verticalHeader().hide()
        self.host_table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.host_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.host_table.itemDoubleClicked.connect(self.host_filter)

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
        self.hosts.setPlaceholderText(' e.g. www.xxx.com|192.168.1.102-105')

        """ Ports Input """
        self.ports = QLineEdit(self)
        self.ports.setPlaceholderText(' e.g. 80|1500-3500, Default common ports')

        """ Interface """
        self.interface = QComboBox(self)
        self.add_interface()

        """ Protocols """
        self.protocols = QComboBox(self)
        self.protocols.addItem("TCP")
        self.protocols.addItem("UDP")
        self.protocols.addItem("SYN")
        self.protocols.addItem("FIN")

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
        grid.addWidget(self.hosts, 0, 1, 1, 4)
        grid.addWidget(QLabel("Port"), 0, 5)
        grid.addWidget(self.ports, 0, 6, 1, 2)

        grid.addWidget(QLabel("Interface"), 1, 0)
        grid.addWidget(self.interface, 1, 1)
        grid.addWidget(QLabel("Protocol"), 1, 2)
        grid.addWidget(self.protocols, 1, 3)
        grid.addWidget(QLabel("Threads"), 1, 4, 1, 2)
        grid.addWidget(self.threadset, 1, 6)
        grid.addWidget(self.threadnum, 1, 7)
        grid.addWidget(self.startbtn, 0, 8)
        grid.addWidget(self.host_table, 2, 8, 3, 1)
        grid.addWidget(self.tableWidget, 2, 0, 3, 8)
        grid.addWidget(self.clearbtn, 1, 8)
        grid.addWidget(self.statusLabel, 5, 0)
        grid.addWidget(self.pbar, 5, 1, 1, 8)

    def start(self):
        if os.geteuid() != 0:
            QMessageBox.information(self, 'Message', 'Root required for Scanner', QMessageBox.Ok, QMessageBox.Ok)
            return
        self.taskQueue.queue.clear()
        """ Get tasks """
        hosts_list = Util.get_hosts_list(self.hosts.text())
        ports_list = Util.get_ports_list(self.ports.text())
        if not hosts_list:
            QMessageBox.information(self, 'Message', 'Invalid host!', QMessageBox.Ok, QMessageBox.Ok)
            return
        if ports_list == "error":
            QMessageBox.information(self, 'Message', 'Invalid port!', QMessageBox.Ok, QMessageBox.Ok)
            return
        if not ports_list:
            ports_list.extend(Util.get_common_port())
        for host in hosts_list:
            for port in ports_list:
                self.taskQueue.put([host, port])

        """ Reset tasks and start process timer """
        self.taskNum = self.taskQueue.qsize()
        self.step = 0
        self.timer.start(100, self)

        """ Clear row contents and start thread """
        self.clear()
        self.threadlist.clear()
        if self.protocols.currentText() == "TCP":
            self.threadlist.extend([Thread(target=self.tcp_scan) for _ in range(self.threadset.value())])
        elif self.protocols.currentText() == "UDP":
            self.threadlist.extend([Thread(target=self.udp_scan) for _ in range(self.threadset.value())])
        elif self.protocols.currentText() == "SYN":
            self.threadlist.extend([Thread(target=self.syn_scan) for _ in range(self.threadset.value())])
        elif self.protocols.currentText() == "FIN":
            self.threadlist.extend([Thread(target=self.fin_scan) for _ in range(self.threadset.value())])

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

    def clear(self):
        self.tableWidget.clearContents()
        self.tableWidget.setRowCount(0)
        self.host_catalog.clear()
        self.host_table.clearContents()
        self.host_table.setRowCount(0)
        self.statusLabel.setText("Stop")
        self.pbar.setValue(0)

    def host_filter(self):
        host = self.host_table.currentItem().text()
        for r in range(self.tableWidget.rowCount()):
            self.tableWidget.setRowHidden(r, False)
        items = self.tableWidget.findItems(host, Qt.MatchExactly)
        for r in range(self.tableWidget.rowCount()):
            if self.tableWidget.item(r, 1) not in items:
                self.tableWidget.setRowHidden(r, True)

    def tcp_scan(self):
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                ip, port = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            sport = RandShort()
            syn = IP(dst=ip) / TCP(sport=sport, dport=int(port), flags='S')
            syn_ack = sr1(syn, iface=self.interface.currentText(), timeout=0.2, verbose=False)
            if syn_ack:
                if syn_ack.getlayer(TCP).flags == 'SA':
                    self.add_table_item(ip, port, 'Open')
                    ack = IP(dst=ip)/TCP(sport=sport, dport=int(port), flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
                    send(ack, iface=self.interface.currentText(), verbose=False)
                elif syn_ack.getlayer(TCP).flags == 'RA':
                    self.add_table_item(ip, port, 'Closed')
            else:
                self.add_table_item(ip, port, "Filtered")
            self.step = self.step + 100 / self.taskNum
        self.scan_finished()

    def udp_scan(self):
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                ip, port = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            sport = RandShort()
            ans = sr1(IP(dst=ip) / UDP(sport=sport, dport=int(port)), timeout=0.2, iface=self.interface.currentText(), verbose=False)
            if ans:
                if ans.haslayer(UDP):
                    self.add_table_item(ip, port, 'Open')
            elif not ans:
                self.add_table_item(ip, port, "Open|Filtered")
            elif ans.haslayer(ICMP):
                if int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) == 3:
                    self.add_table_item(ip, port, "Closed")
                elif int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    self.add_table_item(ip, port, "Filtered")
            self.step = self.step + 100 / self.taskNum
        self.scan_finished()

    def syn_scan(self):
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                ip, port = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            sport = RandShort()
            syn = IP(dst=ip) / TCP(sport=sport, dport=int(port), flags='S')
            syn_ack = sr1(syn, iface=self.interface.currentText(), timeout=0.2, verbose=False)
            if syn_ack:
                if syn_ack.haslayer(TCP):
                    if syn_ack.getlayer(TCP).flags == 'SA':
                        self.add_table_item(ip, port, 'Open')
                        send(IP(dst=ip) / TCP(sport=sport, dport=int(port), flags='R'), iface=self.interface.currentText(), verbose=False)
                    elif syn_ack.getlayer(TCP).flags == 'RA':
                        self.add_table_item(ip, port, 'Closed')
                elif syn_ack.haslayer(ICMP):
                    if int(syn_ack.getlayer(ICMP).type) == 3 and int(syn_ack.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                        self.add_table_item(ip, port, "Filtered")
            elif not syn_ack:
                self.add_table_item(ip, port, "Filtered")
            self.step = self.step + 100 / self.taskNum
        self.scan_finished()

    def fin_scan(self):
        while not self.taskQueue.empty():
            if self.lock: continue
            try:
                ip, port = self.taskQueue.get(block=False)
            except queue.Empty:
                break
            sport = RandShort()
            ans = sr1(IP(dst=ip) / TCP(sport=sport, dport=int(port), flags="F"), timeout=0.2, verbose=False)
            if not ans:
                self.add_table_item(ip, port, "Open|Filtered")
            elif ans.haslayer(TCP):
                if ans.getlayer(TCP).flags == "RA":
                    self.add_table_item(ip, port, "Closed")
            self.step = self.step + 100 / self.taskNum
        self.scan_finished()

    def add_table_item(self, host, port, status):
        rowPosition = self.tableWidget.rowCount()
        self.tableWidget.insertRow(rowPosition)
        self.tableWidget.setItem(rowPosition, 0, QTableWidgetItem(str(rowPosition + 1)))
        self.tableWidget.setItem(rowPosition, 1, QTableWidgetItem(host))
        portItem = QTableWidgetItem()
        portItem.setData(Qt.DisplayRole, int(port))
        self.tableWidget.setItem(rowPosition, 2, portItem)
        self.tableWidget.setItem(rowPosition, 3, QTableWidgetItem(status))
        if host not in self.host_catalog:
            self.host_catalog.append(host)
            position = self.host_table.rowCount()
            self.host_table.insertRow(position)
            self.host_table.setItem(position, 0, QTableWidgetItem(host))

    def scan_finished(self):
        if threading.current_thread() in self.threadlist:
            self.threadlist.remove(threading.current_thread())
        """ When scan too many targets, some threads will auto stop, and cause the result that cannot
            finish expectedly, this is a problem here """
        for t in self.threadlist:
            if "stop" in str(t):
                self.threadlist.remove(t)
        if not self.threadlist:
            self.step = 100
            try:
                self.startbtn.clicked.disconnect(self.stop)
            except TypeError:
                pass
            self.startbtn.setText("Start")
            self.startbtn.clicked.connect(self.start)
            self.tableWidget.sortItems(2, Qt.AscendingOrder)

    def timerEvent(self, e):
        """ Update the process bar """
        self.pbar.setValue(self.step)
        if self.step >= 100:
            self.timer.stop()
            self.statusLabel.setText('Finished')
            return

    def thread_on_changed(self):
        self.threadnum.setText(str(self.threadset.value()))

    def add_interface(self):
        """ Get Adapter interface and ip info """
        self.adapter_info = Util.get_adapter()
        for iface in self.adapter_info.keys():
            self.interface.addItem(iface)

    def stop(self):
        self.timer.stop()
        self.statusLabel.setText("Stop")
        for t in self.threadlist:
            try:
                StopThreading.stop_thread(t)
            except ValueError:
                self.threadlist.remove(t)  # The thread has been stopped
        self.startbtn.setText("Start")
        try:
            self.startbtn.clicked.disconnect(self.stop)
        except TypeError:
            pass
        self.startbtn.clicked.connect(self.start)
