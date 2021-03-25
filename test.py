# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, TCP
from scapy.all import *
import sys

# if len(sys.argv) !=4:
#     print("check usage")
#     sys.exit(0)

# target = str(sys.argv[1])
# startport = int(sys.argv[2])
# endport = int(sys.argv[3])
# print("Scanning" + target +" for open TCP ports\n")

# if startport == endport:
#     endport+=1

# for x in range(startport,endport+1):
#     print(x)
#     pack = IP(dst=target)/TCP(dport=(x), flags='S')
#     response = sr1(pack, timeout=0.5, verbose=0)
#     try:
#         if response.haslayer(TCP) and response.getlayer(TCP).flags==0x12:
#             print('Port '+str(x)+ ' is open!')
#             sr(IP(dst=target)/TCP(dport=response.sport,flags='R'),timeout=0.5,verbose=0)
#     except AttributeError:
#         print('Port '+str(x)+ ' is closed!')

# print("done")



p=sr(IP(dst="192.168.0.0/24")/TCP(flags='S', dport=22),timeout=2)

p.show()


#! /usr/bin/python

# import logging
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# from scapy.all import *

# dst_ip = "192.168.0.23"
# src_port = RandShort()
# dst_port=22

# tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=10)
# if(str(type(tcp_connect_scan_resp))=="<type'NoneType'>"):
#     print("Closed")
# elif(tcp_connect_scan_resp.haslayer(TCP)):
#     if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
#         send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
#         print("Open")
# elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
#     print ("Closed")