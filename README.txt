Project: Ping Zombie
An early prototype of a network scanner script that will use TCP + ICMP to scan a network and search for targets that can be used as zombies in an TCP idle port scan.

Version Control:

1.0:
	Initial version fully-functioning version, takes IP and sends ICMP and TCP pings, prints packet data

planned versions:

1.1:
	Make a more useful verbose mode.


files:
ICMPSession.py
	Object-oriented method of getting data from ICMP echo packets, gives packet data, delay times, etc.
TCPSession.py
	Object-oriented method of sending multiple TCP "pings", similar in implementation to a SYN scan
helpers.py
	a few common methods used across TCP and ICMP network code.
zombiescanner.py
	Our main method that launches the TCP and ICMP scans.

Usage:
//default scan using port 80
~# python zombiescanner.py 10.0.0.1
//specify port 455 for TCP scan
~# python zombiescanner.py 10.0.0.1 455

~~~~~Examples~~~~~

Pinging a host running raspbian 7.6:

# python zombiescanner.py 192.168.1.150

#### zombie scanner - IP/TCP header data collection ####

data for host: 192.168.1.150, TCP port: 80 is open
5 packets sent, 5 packets received, 0 timeouts
avg delay=0.474ms
icmp ipid=[19581, 19582, 19583, 19584, 19585]
tcp ipid=[0, 0, 0, 0, 0]

pinging a host running Ubuntu 12.04.3 LTS on a closed port

#### zombie scanner - IP/TCP header data collection ####

data for host: 192.168.1.151, TCP port: 21 is closed
5 packets sent, 5 packets received, 0 timeouts
avg delay=0.414ms
icmp ipid=[11808, 11809, 11810, 11811, 11812]
tcp ipid=[11815, 11816, 11817, 11818, 11819]
