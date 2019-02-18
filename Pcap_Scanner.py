from scapy.all import *
import socket   
import argparse
import sys


def host_ports(pack):
    ips={}
    info_port=()
    for pkt in pack:
        if pkt.getlayer(IP):
            ip=pkt[IP].src
            if pkt.getlayer(UDP):
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
            elif pkt.getlayer(TCP):
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
            elif pkt.getlayer(ICMP):

                info_port=('ICMP')
                ips.setdefault(ip, {})[''] =info_port         

    list=sorted(ips.items(), key=lambda x:x[1], reverse = True)
    return list
def dis_os(pack):
    ttl =0
    win=0
    os={}
    sip=0
    ch=''
    for pkt in pack:   
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
    #pack = rdpcap("/home/muhammed/share/test.pcapng")
    pack=rdpcap(pck)	
    list=host_ports(pack)
    os=dis_os(pack)
    for host,port1 in list:
        print("[+]    Host: "+host+"    [+]")
        print("[+]    Open ports and services :"),
        print (port1),
        print ("    [+]")
        print("[+]    Possible OS = "),
        print (os.get(host)),
        print("    [+]\n")

if __name__ == '__main__':
    main()
