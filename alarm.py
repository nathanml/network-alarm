from scapy.all import *
import argparse
import base64

incidentNum = 0
incidents = []
userStack = []

def packetcallback(packet):
  try:
    if TCP in packet:
      tcp = packet[TCP]
      ip = packet[IP]
      payload = tcp.load.decode("ascii").strip()
      nullscan(ip, tcp)
      finscan(ip, tcp)
      xmasscan(ip, tcp)
      niktoscan(packet, payload)
      smbscan(ip, tcp)
      rdpscan(ip, tcp)
      vncscan(ip, tcp)
      findusernamesandpasswords(packet)
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    pass
    #print("pass")

# Null scan function implementation
def nullscan(ip, tcp):
  if tcp.flags== None:
    incident = "Null scan is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    addIncident(incident)

# FIN scan
def finscan(ip, tcp):
  if tcp.flags == 'F':
    incident = "FIN scan is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    addIncident(incident)

def xmasscan(ip, tcp):
  if tcp.flags == 'FPU':
    incident = "Xmas scan is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    addIncident(incident)

def niktoscan(packet, payload):
  if "Nikto" in payload:
    incident = "Nikto scan is detected from " + str(packet[IP].src) + " (Port " + str(packet[TCP].dport) + ")!"
    addIncident(incident)

def smbscan(ip, tcp):
  if tcp.dport == 445 or tcp.dport == 139:
    incident = "Server Message Block (SMB) protocol is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    print(incident)
    addIncident(incident)
  
def rdpscan(ip, tcp):
  if tcp.sport == 3389:
    incident = "Remote Desktop Protocol (RDP) is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    addIncident(incident)

def vncscan(ip, tcp):
  if tcp.sport == 5900:
    incident = "Virtual Network Computing (VNC) instance scan is detected from " + str(ip.src) + " (Port " + str(tcp.dport) + ")!"
    addIncident(incident)

def findusernamesandpasswords(packet):
  payload = str(packet[Raw].load)

  #Check for credentials sent over FTP
  if(packet[TCP].dport == 21):
    if "USER" in payload:
      username = payload.split()[1][:-5]
      userStack.append(username)
    if "PASS" in payload:
      password = payload.split()[1][:-5]
      username = userStack.pop()
      incident = "Usernames and passwords sent in-the-clear (FTP) (Username: " + username + ", Password: " + password + ")"
      addIncident(incident)
      

  #Check for credentials sent over IMAP
  if(packet[TCP].dport == 143):
    if "LOG IN" in payload or "LOGIN" in payload:
      firstplit = payload[4:-4].split('"')
      password = firstplit[1]
      username = firstplit[0].split(" ")[2].split("@")[0]
      incident = "Usernames and passwords sent in-the-clear (IMAP) (Username: " + username + ", Password: " + password + ")"
      addIncident(incident)

  #Check for credentials sent via Basic Auth with HTTP
  if "Authorization: Basic" in payload:
    basicToken = payload.split("Authorization: Basic ")[1].split("\\r\\n")[0]
    decoded = str(base64.b64decode(basicToken))
    credentials = decoded[1:].replace("'", "").split(":")
    username = credentials[0]
    password = credentials[1]
    incident = "Usernames and passwords sent in-the-clear (HTTP) (Username: " + username + ", Password: " + password + ")"
    addIncident(incident)

def addIncident(incident):
  incidents.append(incident)
  size = len(incidents)
  print("ALERT #" + str(size) + ": " + incident)


# Code below for parsing arguments
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")