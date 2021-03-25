from scapy.layers.inet import IP
from scapy.all import *

a = IP(dst="192.168.1.1/24")

print(a.fields.values())


# if __name__ == "__main__" :
#     if len(sys.argv) !=3:
#         print("usage: %s [target or target/subnet mask prefix e.g 192.168.1.1/24] [single port or startport] [endport - optional]" % (sys.argv[0]))
#         sys.exit(0)