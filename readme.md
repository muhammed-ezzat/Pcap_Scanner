					

====================
# Pcap_Scanner
==================== 



---------------
## What 's this
---------------
### Pcap_Scanner is tool that passively scan to a Pcap file and determine:

[-] Host ip [-] 
[-] Open ports [-]
[-] Identified Protocols [-]
[-] Operating System [-]



## A snippet of typical Pcap_Scanner output may look like this:

	[+]    Host: 1.2.3.4    [+]
	[+]    Open ports and services : {80: ('TCP', 'http'), 443: ('TCP', 'https')}     [+]
	[+]    Possible OS =   Linux kernel 2.x    [+]


	[+]    Host: 5.6.7.8    [+]
	[+]    Open ports and services : {123: ('UDP', 'ntp')}     [+]
	[+]    Possible OS =  OpenBSD    [+]



	[+]    Host: 10.0.2.3    [+]
	[+]    Open ports and services : {53: ('UDP', 'domain'), 22: ('TCP', 'ssh')}     [+]
	[+]    Possible OS =  Windows:NT kernel 6.x     [+]



----------------
## Requirements :
----------------

- python2.7          https://www.python.org/downloads/release/python-2713/

- scapy              https://scapy.net/


------------------
## How to use it ?
------------------

python Pcap_Scanner.py file
