from scapy.layers.inet import IP,Ether,TCP,ICMP
from scapy.all import *
from scapy.layers.l2 import *
import argparse
from datetime import datetime as dt
import socket

def arp_scan(target):
    #Dictionary to save all the host results including: IP address, Open Ports, Mac Address and Latency

    results = {}
    """
    shape of results: 
    results = {
        "192.168.0.1":{
            "MAC" = "xxx",
            "latency" = "xxxx",
            "open_ports" = [1,2,3,4],
            "filtered_ports"= [56]
        },
        "192.168.0.2":{
            "MAC" = "xxx",
            "latency" = "xxxx",
            "open_ports" = [1,2,3,4],
            "filtered_ports"= [56]
    }

    """
    # Broadcast ARP request to the network to find live hosts. Verbose of 0 to supress screen logging
    # Stuck the Layer 2 and Layer 3 packets
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.0.0/24")
    
    # Send the packets using the scapy srp() method.
    ans,_ = srp(arp_packet,timeout=10,verbose=0)

    # Find this host's IP address.
    self_hostname = socket.gethostname()
    self_ip= socket.gethostbyname(self_hostname)
    
    # Enumerate all asnwers and append to result dictionary as required
    for answer in ans:
        # If the ip address of the host found in the same as the host scanning, don't append to the dictionary
        if answer[1].psrc != self_ip:
            #results = answer[1].psrc
            results[answer[1].psrc] = {
                "MAC Address":answer[1].hwsrc,
                "latency": (answer[0][0].sent_time - answer[0][1].time)*1000, # convert to ms
                "open_ports": []
                }
    
    return results

def TCP_SYN_port_scan(dict, ports):
    hosts = dict
    # scan the hosts for open TCP ports as listed in the provided dictionaty
    for host in hosts:
        print(host)
        # Stuck the Layer 3 header and the TCP payload
        tcp_package = IP(dst=host) / TCP(dport=ports, flags="S")
        ans,_ = sr(tcp_package, timeout=2, verbose= False)
        for answer in ans:
            if answer[1][TCP].flags == 0x12:
                print("test")
                hosts[host]["open_ports"].append(answer[1][TCP].sport)
                
    return hosts

def print_report(results):
    #extract the hosts to a list
    hosts = []
    for host in results:
        hosts.append(host)
    #sort hosts smaller to bigger:
    hosts.sort()
    # Enumerate all hosts and print the report

    for host in hosts:
        print("TCP_SYN Scan report for {}".format(host))
        print("Host is up ({}s latency).".format(results[host]["latency"]))
        if len(results[host]["open_ports"]) == 0:
            print("All specified for scan ports on {} are most likely filtered or closed".format(host))
        else:
            print("PORT\tSTATE\tSERVICE")
            try:
                for port in results[host]["open_ports"]:
                    print("{}/tcp\topen\t{}".format(port, socket.getservbyport(int(port))))
            except socket.error:
                    print("{}/tcp\topen\t uknown".format(port))
        print("MAC Address: {}".format(results[host]["MAC Address"]))
        print("")
    pass

def save_report(filename):
    pass





if __name__ == "__main__" :
   
    # Parse all the arguments from command line.
    # Use -h for help and how to use.
    parser = argparse.ArgumentParser(description="TCP_SYN Scan. Please provide target and port(s). Use -h for help")
    parser.add_argument("-t", "--target", dest = "target", required=True, help="Target or target/subnet mask prefix e.g 192.168.1.1/24 for the scan")
    parser.add_argument("-p", "--port", dest = "port", type = int, help="Specific port to scan. Example usage: -p 22.")
    parser.add_argument("-pr", "--portrange", dest = "portrange", type = int,nargs=2, help="Range of ports to scan. Example usage: -pr 1 100.")
    parser.add_argument("-pl", "--portlist", dest = "portlist", type=int,nargs="+", help="List of specific ports to scan. Example usage: -pl 1 10 23.")
    parser.add_argument("-l", "--logfile",dest = "logfile", help="Optional. File name to save the results. If not provided, default name will be used")

    args = parser.parse_args()

    #Check that at maximum 1 port argument is provided. 
    if (args.port or args.portrange or args.portlist) is None:
        print("Error! Port not provided. See --help for details.\nExiting..")
        sys.exit(1)
    elif [args.port, args.portrange, args.portlist].count(None) < 2:
        print("Error! Too many port arguments given. Only one type of port scan is required. See --help for details.\nExiting..")
        sys.exit(1)

    # check which port scan option selected and assign to port variable.
    if args.port is not None:
        port = args.port
    elif args.portrange is not None:
        port = tuple(args.portrange)
    else: 
        port = args.portlist

    # Get the target from the arguments on which to perform the TCP_SYN Scan
    target = args.target
    # If specified, get the filename argument which will be used to save the results, otherwise use the default "TCP_SYN report + current time"
    if args.logfile is not None:
        filename = args.logfile
    else:
        now = dt.now()
        time_filename = now.strftime("%Y-%m-%d-%H-%M-%S")
        filename = str("TCP_SYN_"+time_filename+".txt") 

    
    print("Starting TCP_SYN Scan at {}.\nTarget: {}\nPort(s): {}\nResults will be saved under \"{}\" ".format(
            now.strftime("%Y-%m-%d %H:%M:%S"),
            target,
            port,
            filename
            ))
    
    #4 main steps:
    
    #1) ARP scan the network for live hosts
    print("Scanning the network for live host(s)...")
    live_hosts = arp_scan(target)
    print(live_hosts)
    print("Found {} live hosts".format(len(live_hosts)))
    print("Scanning for open TCP ports on live hosts...")
    tcp_scan = TCP_SYN_port_scan(live_hosts, port)
    print(tcp_scan)
    print_report(tcp_scan)



    # ip= args.target
    # port = args.port
    # log = args.logfile
    # print(port)

    # print(arg)
    # print(type(port))