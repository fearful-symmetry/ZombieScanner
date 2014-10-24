"""
zombie scanner
Launcher script
"""

import sys
import argparse
from libs.ICMPSession import *
from libs.TCPSession import *
from libs.TCPScanner import scan_addr

def check_ipv4(addr):
    """
    checks to make sure we have a real IPv4 address
    """

    addr_bytes = addr.split(".")

    if not len(addr_bytes) == 4:
        return False

    for the_bytes in addr_bytes:
        if not the_bytes.isdigit():
            return  False

    for the_bytes in addr_bytes:
        if int(the_bytes) > 255:
            return False

    return True


def main():
    """
    Main method for our launcher
    """
    parser = argparse.ArgumentParser(description='Get IP, port and other options')
    parser.add_argument('dest', help="the IP adress to  ping")
    parser.add_argument('port', nargs='?', default =80, type=int, help="remote host port number")
    parser.add_argument("-v","--verbose",help="print more TCP/ICMP data", action="store_true")

    #more compact vars for cmd ln args
    args = parser.parse_args()
    addr = args.dest
    port = args.port
    verb = args.verbose


    if check_ipv4(addr):
        print ''
        #tcp_id, port_status = scan_addr(addr, port)
        #ICMP scanning
        pings = ICMPSession(addr)
        pings.start_ping(5)

        #TCP scan
        port_list = [port] * 5
        scans = TCPSession(addr)
        scans.scan_addr_at_port(port_list)
        last_tcp = scans[-1]

        tcp_id = last_tcp['IPID']
        port_status = last_tcp['status']

        #print status of port
        if port_status == "filtered":
            print'data for host: {}, TCP port: {} is filtered'.format(addr, port)
        elif port_status == "open":
            print 'data for host: {}, TCP port: {} is open'.format(addr, port)
        else:
           print 'data for host: {}, TCP port: {} is closed'.format(addr, port)

        #prints lists of data from host
        pings.print_stats()
        print 'avg delay={}ms'.format(pings.delay())
        print 'icmp ipid={}'.format(pings.get_header_item_list("IPID"))
        print 'tcp ipid={}'.format(scans.get_header_item_list("IPID"))


        if verb:
            print ''
            print "Data from last ICMP packet:"
            print pings.print_dict()

        print ''
    else:
        print 'invalid IPv4 addr'


if __name__ == '__main__':
    main()
