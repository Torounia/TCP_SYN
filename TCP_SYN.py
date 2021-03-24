from scapy.all import *

a=IP(dst="192.168.0.0/24")

print([type(p) for p in a])