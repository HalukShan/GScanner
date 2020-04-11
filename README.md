## GScanner
A comprehensive scanner developed by python3 for MacOS/Linux, using pyqt5 to design GUI, and 
using scapy to develop network scan function. (Directory scan is developing...)
if you use windows, you should install winpcap first.

### Host Detect
Input the target host, use '|' to split, and '-' to specify a range. Choose 
the network interface on your device, the protocol you want to use, 
and the threads number.


### Port Scan
Port scan funtion provide TCP, UDP, SYN, FIN method to scan target. In host table
, when you finished scan you can double click the host to filter the results.