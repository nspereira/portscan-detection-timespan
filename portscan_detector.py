import sys
import os
from time import time
from scapy.all import sniff

ip_to_ports = dict()

ports = 10
timespan = 8

def detect_portscan(packet):
    ip = packet.getlayer('IP')
    tcp = packet.getlayer('TCP')
    
    ip_to_ports.setdefault(ip.src, {})[str(tcp.dport)] = int(time())
    
    if len(ip_to_ports[ip.src]) >= ports:
        scanned_ports = ip_to_ports[ip.src].items()
        
        for (scanned_port, scan_time) in scanned_ports:
        
            if scan_time + timespan < int(time()):
                del ip_to_ports[ip.src][scanned_port]
                
        if len(ip_to_ports[ip.src]) >= ports:
            print "Portscan detected from " + ip.src
            print "Scanned ports " + ",".join(ip_to_ports[ip.src].keys()) + "\n"
            
            del ip_to_ports[ip.src]
            
if len(sys.argv) < 2:
    print sys.argv[0] + '<interface>'
    sys.exit(0)
    
sniff(prn=detect_portscan, filter='tcp', iface=sys.argv[1], store=0)
