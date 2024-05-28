# network-alarm
An alarm written in python to detect various network attacks and vulnerabilities on a server

# dependencies
Install the following dependencies prior to compilation.
```
pip install scapy
pip install argparse
pip install base64
```

# instructions
Run: 
```
sudo python3 alarm.py
```
By default with no arguments, the tool shall sniff on network interface eth0. NOTE: this will not work on macOS because macOS uses en for network interfaces. The tool must handle three command line arguments:
```
-i INTERFACE: Sniff on a specified network interface 
-r PCAPFILE: Read in a PCAP file 
-h: Display message on how to use tool
```
### Example 1: sudo python3 alarm.py -h shall display something of the like:

`usage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]

A network sniffer that identifies basic vulnerabilities

optional arguments: -h, --help show this help message and exit -i INTERFACE Network interface to sniff on -r PCAPFILE A PCAP file to read`

NOTE: sniffing on network interfaces requires sudo.

### Example 2: python3 alarm.py -r set2.pcap will read the packets from set2.pcap. NOTE: reading PCAP files via Scapy or a Python program does not require sudo.

### Example 3: sudo python3 alarm.py -i en0 will sniff packets on a wireless interface en0

When sniffing on a live interface, the tool must keep running. To quit it, press Control-C

# summary
This program can be used to monitor network traffic or read packet capture files and successfully detect any of the following events:
	1. NULL scan
	2. FIN scan
	3. Xmas scan
	4. Usernames and passwords sent in-the-clear via HTTP Basic Authentication, FTP, and IMAP
	5. Nikto scan
	6. Someone scanning for Server Message Block (SMB) protocol
	7. Someone scanning for Remote Desktop Protocol (RDP)
	8. Someone scanning for Virtual Network Computing (VNC) instance(s)

All of the above events have been implemented correctly based in their respective helper functions (more on that below). I worked on this lab individually and I spent roughly 8-10 hours on the assignment (including time at the beginning learning about scapy). In addition to scapy and argparse, I imported base64 to decrypt the base64 encoded credentials sent over HTTP.

Functions:
packetcallback(packet) -> Called on each packet on the network or in the pcap. Calls all helper functions for performing scans
nullscan(ip, tcp) -> Detects if packet is null scan (no flags set)
finscan(ip, tcp) -> Detects if packet is fin scan (FIN flag set)
xmasscan(ip, tcp) -> Detects if packet is xmas scan (FIN, PSH, URG flags set)
niktoscan(payload) -> Detects if Nikto packet by scanning packet payload for Nikto
smbscan(ip, tcp) -> Scans for server message block (destination ports 445 and/or 139)
rdpscan(ip, tcp) -> Scans for someone using remote desktop protocol (port 3389)
vncscan(ip, tcp) -> Scans for VNC instance (port 5900)
findusernamesandpasswords(packet) -> Detects unencrypted credentials sent over FTP (port 21), IMAP (port 143), and HTTP by searching for various keywords in the packet payload (e.g. LOGIN, Basic etc.)
addIncident(incident) -> Method for tracking the incident counter and printing the alert message