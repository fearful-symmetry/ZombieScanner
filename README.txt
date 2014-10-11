Project: Ping Zombie
An early prototype of a network scanner script that will use TCP + ICMP to scan a network and search for targets that can be used as zombies in an TCP idle port scan.

Version Control:

1.0:
Initial version, proof of concept  to show IPID can be extracted from a ping packet using python libraries

1.5:
Added prototype TCP ping. grabs IPID from TCP

Next version:
Full port scanning, algos for IPID incrementation type



files:
ICMPSession.py
	Object-oriented method of getting data from ICMP echo packets, gives packet data, delay times, etc.
TCPScanner.py
	Implements a basic TCP ping and returns the IPID.
zombiescanner.py
	Our main method that launches the TCP and ICMP scans

Usage:
#default scan using port 80
~# python zombiescanner.py 10.0.0.1
#specify port 455 for TCP scan
~# python zombiescanner.py 10.0.0.1 455
