"""
Implementation of TCP_SYN Scan similar to Nmap scanenr using the scapy library and python 2.7. 
Results are both presensted to the screen and saved to file.

"""

from __future__ import print_function
from scapy.layers.inet import IP,Ether,TCP,ICMP
from scapy.all import *
from scapy.layers.l2 import *
import argparse
from datetime import datetime as dt
import socket
import timeit
import ipaddress

def arp_scan(target):
    """
    target: the targer host(s) to perform the TCP_SYN scan. type string
    """
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
        }
    }

    """
    # Broadcast ARP request to the network to find live hosts.
    # Verbose of 0 to supress screen logging
    # Stuck the Layer 2 and Layer 3 packets
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target)
    
    # Send the packets using the scapy srp() method.
    ans,_ = srp(arp_packet,timeout=10,verbose=0)
    
    # Enumerate all asnwers and append to result dictionary as required
    for answer in ans:
        results[answer[1].psrc] = {
            "MAC Address":answer[1].hwsrc,
            "latency": (answer[0][0].sent_time - answer[0][1].time)*1000, # convert to ms
            "ports": []
            }
    
    return results

def TCP_SYN_port_scan(dict, ports):
    """
    dict: a dictionary generated from the function arp_scan. type dictionary
    ports: the port(s) or range of ports to scan. type int, tuple or list 
    """
    hosts = dict
    # scan the hosts for open TCP ports as listed in the provided dictionaty
    for host in hosts:
        print(host)
        # Stuck the Layer 3 header and the TCP payload
        tcp_package = IP(dst=host) / TCP(dport=ports, flags="S")
        #send the TCP package  for  all ports and collect all answers
        ans,_ = sr(tcp_package, timeout=2, verbose= False)
        # for each of the answers received,
        for answer in ans:
            # if the answer is "SYN AKN" or 0x12 in hex, append the port to the results dictonary
            if answer[1][TCP].flags == 0x12:
                hosts[host]["open_ports"].append(answer[1][TCP].sport)
                
    return hosts

def print_save_report(results):
    """
    results: the complete dictionary that stores all the results. type dictionary
    """
    # Find this host's IP address. It will be used to print the results last.
    self_hostname = socket.gethostname()
    self_ip= socket.gethostbyname(self_hostname)
    #extract the hosts to a list
    hosts = []
    for host in results:
        if host != self_ip:
            hosts.append(host)
    
    #sort host IPs smaller to bigger:
    hosts.sort()

    #last add the to the print list the ip of the host that performed the scan
    if self_ip in results:
        hosts.append(self_ip)
        
    # Enumerate all hosts and print the report
    for host in hosts:
        print("TCP_SYN Scan report for {}".format(host))
        print("TCP_SYN Scan report for {}".format(host), file=savefile)
        print("Host is up ({}ms latency).".format(results[host]["latency"]))
        print("Host is up ({}ms latency).".format(results[host]["latency"]), file= savefile)
        if len(results[host]["open_ports"]) == 0:
            print("All specified for scan ports on {} are most likely filtered or closed".format(host))
            print(
                "All specified for scan ports on {} are most likely filtered or closed"\
                    .format(host), file= savefile)
        else:
            print("PORT\t  STATE\t  SERVICE")
            print("PORT\t  STATE\t  SERVICE", file= savefile)
            try:
                for port in results[host]["open_ports"]:
                    print("{}/tcp\t  open\t  {}".format(port, socket.getservbyport(int(port))))
                    print("{}/tcp\t  open\t  {}".format(port, socket.getservbyport(int(port))), file= savefile)
            except socket.error:
                    print("{}/tcp\t  open\t  uknown".format(port))
                    print("{}/tcp\t  open\t  uknown".format(port), file=savefile)
        print("MAC Address: {}".format(results[host]["MAC Address"]))
        print("MAC Address: {}".format(results[host]["MAC Address"]), file= savefile)
        print("")
        print("", file=savefile)
    

if __name__ == "__main__" :
   
    # Parse all the arguments from command line.
    # Use -h for help and how to use.
    parser = argparse.ArgumentParser(
        description="TCP_SYN Scan. Please provide target and port(s). Use -h for help")
    parser.add_argument("-t", "--target", dest = "target", required=True,\
        help="Target or target/subnet mask prefix e.g 192.168.1.1/24 for the scan")
    parser.add_argument("-p", "--port", dest = "port", type = int,\
        help="Specific port to scan. Example usage: -p 22.")
    parser.add_argument("-pr", "--portrange", dest = "portrange", type = int,nargs=2,\
        help="Range of ports to scan. Example usage: -pr 1 100.")
    parser.add_argument("-pl", "--portlist", dest = "portlist", type=int,nargs="+", \
        help="List of specific ports to scan. Example usage: -pl 1 10 23.")
    parser.add_argument("-l", "--logfile",dest = "logfile", \
        help="Optional. File name to save the results. If not provided, default name will be used")

    args = parser.parse_args()

    #Check that at maximum 1 port argument is provided. 
    if (args.port or args.portrange or args.portlist) is None:
        print("Error! Port not provided. See --help for details.\nExiting..")
        sys.exit(1)
    elif [args.port, args.portrange, args.portlist].count(None) < 2:
        print("Error! Too many port arguments given.\
            Only one type of port scan is required. See --help for details.\nExiting..")
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
    # If specified, get the filename argument which will be used to save the results,
    #   otherwise use the default "TCP_SYN report + current time"
    
    if args.logfile is not None:
        filename = args.logfile
    else:
        now = dt.now()
        time_filename = now.strftime("%Y-%m-%d-%H-%M-%S")
        filename = str("TCP_SYN_"+time_filename+".txt") 
    savefile = open(filename, "a")

    ## All statements are printed to both the screen and to a file.
    time_now = dt.now()
    print("Starting TCP_SYN Scan at {}.\nTarget: {}\nPort(s): {}\nResults will be saved under \"{}\" "\
        .format(
            time_now.strftime("%Y-%m-%d %H:%M:%S"),
            target,
            port,
            filename
            ))
    print("Starting TCP_SYN Scan at {}.\nTarget: {}\nPort(s): {}\nResults will be saved under \"{}\" "\
        .format(
            time_now.strftime("%Y-%m-%d %H:%M:%S"),
            target,
            port,
            filename
            ), file=savefile)
    
    # Mark the start time of the scan.
    start_scan_time = timeit.default_timer()

    print("Scanning the network for live host(s)...")
    print("Scanning the network for live host(s)...", file =savefile)
    
    #Step 1) Find live hosts in the network.  
    live_hosts = arp_scan(target)
    print("Found {} live hosts".format(len(live_hosts)))
    print("Found {} live hosts".format(len(live_hosts)), file= savefile)
    
    print("Scanning for open TCP ports on live hosts...")
    print("Scanning for open TCP ports on live hosts...", file= savefile)
    #Step 2) Scan for open TCP ports on the live hosts
    tcp_scan = TCP_SYN_port_scan(live_hosts, port)

    #Step 3) Print and save the report
    print_save_report(tcp_scan)

    # Mark the scan stop time.
    scan_completed_time = timeit.default_timer()

    print("TCP Scan completed in {} seconds".format(scan_completed_time-start_scan_time))
    print("TCP Scan completed in {} seconds".format(scan_completed_time-start_scan_time), file= savefile)

    # Save and close the log file
    savefile.close()
    
    