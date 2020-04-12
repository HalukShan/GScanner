## GScanner
A Comprehensive network scanner developed by python for MacOS/Linux.
 It uses pyqt5 to design GUI and scapy to develop network scanning function. 
 
 Scanner provides host detection scanning based on `ICMP` Protocol and `ARP`
 protocol, and port scanning of LAN or public network
 devices based on `TCP` protocol and `UDP` protocol, and supports stealth 
 scanning, such as `SYN` scanning and `FIN` scanning. This type of scanning 
 does not establish a three-way handshake, but also speeds up the scanning 
 speed.
 
 if you use windows, you should install `winpcap` first.

### Usage
```
git clone https://github.com/HalukShan/GScanner.git
cd GScanner
sudo python3 GScanner.py
```
The program requires root permission. If it is not opened as root, 
a prompt will be given.

### Host Detect
Host detection function provides packet detection based on `ICMP` Protocol 
or `ARP` protocol. `ARP` protocol is mainly used for rapid detection of LAN host.
 ARP scan use multi-thread `send()` and single thread to `sniff`.
  It sends data packets in batch through broadcast. Sniff filters out `is at`
   reply. The whole network segment can be scanned in 2-3 seconds.

### Port Scan
The port scanning function supports `TCP`, `UDP`, `SYN` and `FIN` mode 
scanning, and classifies the results by host. 
You can `double-click` the host item on the right to filter and view the 
scanning results under the corresponding host. Multi thread sending is 
supported. It is measured that `1000` ports are scanned under `16` threads 
for about `13` seconds.
