## GScanner
A Comprehensive network scanner developed by python for MacOS/Linux.
 It uses pyqt5 to design GUI and scapy to develop network scanning function. 
 
 Scanner provides host detection scanning based on `ICMP` Protocol and `ARP`
 protocol, and port scanning of LAN or public network
 devices based on `TCP` protocol and `UDP` protocol, and supports stealth 
 scanning, such as `SYN` scanning and `FIN` scanning. 

### Usage
```
git clone https://github.com/HalukShan/GScanner.git
cd GScanner
pip3 install -r requirements.txt
sudo python3 GScanner.py
```
The program requires root permission. If it is not opened as root, 
a prompt will be given.

### Host Detect
Host detection function provides packet detection based on `ICMP` Protocol 
or `ARP` protocol. 
   
![](https://github.com/HalukShan/GScanner/blob/master/Img/gs1.jpg)

### Port Scan
The port scanning function supports `TCP`, `UDP`, `SYN` and `FIN` mode 
scanning, and classifies the results by host. 
You can `double-click` the host item on the right to filter and view the 
scanning results under the corresponding host. Multi thread sending is 
supported. 

![](https://github.com/HalukShan/GScanner/blob/master/Img/gs2.jpg)
