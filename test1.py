# # import logging
# # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# from socket import timeout
# from scapy.layers.inet import ICMP, IP, TCP
# from scapy.layers.l2 import *
# from scapy.all import *
# import sys
# import socket


# #https://stackoverflow.com/questions/19636817/python-get-computers-ip-address-and-host-name-on-network-running-same-applica
# hostname = socket.gethostname()
# ip= socket.gethostbyname(hostname)

# # Stuck the Layer 2 and Layer 3 packets
# arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.0.0/24")
# ans,_ = srp(arp_packet,timeout=10,verbose=0)




# print(ans.show())
# ans_ips = [a[1].hwsrc for a in ans]
# # Latency = https://stackoverflow.com/questions/59432123/how-to-measure-time-from-send-and-receive-in-scapy

# times = [(a[0][0].sent_time - a[0][1].time)*1000  for a in ans]

# # if ip in ans_ips:
# #     ans_ips.remove(ip) 

# print(list(ans_ips))
# print(list(times))



# # for ip in ans_ips:
# #     print(ip)
# #     for port in range(0,100):
# #         print("trying port", port)
# #         res = sr1(IP(dst=ip)/TCP(flags="S", dport=port),timeout=5,verbose=0)
# #         if res is not None:
# #             print(ip,port)
# #             if res[TCP].flags == "SA":
# #                 print(res[TCP].sport)
# #         else:
# #             print(res)
#     #     try:
#     #         if res.haslayer(TCP):
#     #             print(res.summary())
#     #             if res.getlayer(TCP).flags == 0x12:
#     #                 print("port {} is open".format(port))
#     #     except AttributeError:
#     #         print("No TCP layer")
#     # #print(type(res.show()))

# # def tcp_scan(ip, ports):
# #     try:
# #         syn = IP(dst=ip) / TCP(dport=ports, flags="S")
# #     except socket.gaierror:
# #         raise ValueError('Hostname {} could not be resolved.'.format(ip))

# #     ans, unans = sr(syn, timeout=2, retry=1)
# #     result = []

# #     for sent, received in ans:
# #         if received[TCP].flags == "SA":
# #             result.append(received[TCP].sport)

# #     return result

# # print(tcp_scan("192.168.0.56",(1,23)))


import ipaddress



adrs = "192.168.0.100/24"
adrs2 = "192.168.0.1"

if "/" in adrs:
    print("Found")
    a = ipaddress.ip_interface(unicode(adrs))
    print(str(a.network))
    b = ipaddress.ip_network(a.network)
    c = map(str, b.hosts())
    print (type(c))

a_ = ipaddress.ip_address(unicode(adrs2))

print([str(a_)])



