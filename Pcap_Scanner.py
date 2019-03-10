from scapy.all import *
import socket   
import argparse
import sys


def host_ports(pck):
    ips={}
    info_port=()
    with PcapReader(pck) as pr:
        for pkt in pr:
            if pkt.getlayer(IP):
                ip=pkt[IP].src
                if UDP in pkt:
                    port=pkt.sport
                    ips.setdefault(ip, {})
                    if ip in ips:
                        if port in ips[ip]:
                            pass
                        else:
                            try:
                                info_port=('UDP',socket.getservbyport(port))
                            except:
                                info_port=('UDP','not defined')
                            ips.setdefault(ip, {})[port] =info_port
                elif TCP in pkt:
                    port=pkt.sport
                    ips.setdefault(ip, {})
                    if ip in ips:
                        if port in ips[ip]:
                            pass
                        else:
                            try:
                                info_port=('TCP',socket.getservbyport(port))
                            except:
                                info_port=('TCP','not defined')
                            ips.setdefault(ip, {})[port] =info_port
                elif ICMP in pkt:

                    info_port=('ICMP')
                    ips.setdefault(ip, {})[''] =info_port         

    lst=sorted(ips.items(), key=lambda x:x[1], reverse = True)
    return lst
def dis_os(pck):
    ttl =0
    win=0
    os={}
    sip=0
    ch=''

    with PcapReader(pck) as pr:
        for pkt in pr:   
            if pkt.getlayer(IP) and pkt.getlayer(TCP):
                sip=pkt[IP].src
                ttl=pkt[IP].ttl
                win=pkt.window
                ip=pkt[IP].src
                if ttl==128:
                    if win==65535 or win ==16384:
                        ch=("Windows:NT kernel 5.x") 
                    elif win==8192:
                        ch= ("Windows:NT kernel 6.x")
                    else:
                        ch= ("Windows:NT kernel")
                elif ttl==64:
                    if win==5840:
                        ch= ("Linux kernel 2.x ")
                    elif win==5720:
                        ch= ("Google Linux (Android/chromeOS)")
                    elif win==65535:
                        ch= (" FreeBSD")
                    elif win==16384:
                        ch= ("OpenBSD")
                    elif win==32850:
                        ch= ("Solaris")
                    else:
                        ch=(" Unknown")
                elif ttl==255:
                    if win ==4128:
                        ch= ("iOS 12.4 (Cisco Routers)")
                else:
                    ch= ("Unknown")
                if sip not in os:
                    os.setdefault(sip,ch)
    return os 

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", nargs='?', default="check_if_empty" , help="the pcap file directory")
    args = parser.parse_args()
    if args.file == 'check_if_empty':
        print ('Enter the file directory')
        exit(2)
    elif args.file.endswith('.pcap') == False:
        print ('Enter a pcap file')
        exit(2)
    else:
        pck =args.file    
    
    	
    lst=host_ports(pck)
    os=dis_os(pck)
    for host,port1 in lst:
        print("[*]    Host: "+host+"    [*]")
        print("[*]    Open ports and services :"),
        print (port1),
        print ("    [*]")
        print("[*]    Possible OS = "),
        print (os.get(host)),
        print("    [*]\n")

if __name__ == '__main__':
    main()
