"""
zombie scanner
Launcher script
"""

import sys
import argparse
from libs.ICMPSession import *
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

    args = parser.parse_args()
    addr = args.dest
    port = args.port
    verb = args.verbose


    if check_ipv4(addr):
        print ''
        #print 'tcp ipid={}'.format(scan_addr(addr, port))
        tcp_id, port_status = scan_addr(addr, port)
        pings = ICMPSession(addr)
        pings.start_ping(5)


        if tcp_id == None:
            print'data for host: {}, TCP port: {} is filtered'.format(addr, port)
        elif port_status:
            print 'data for host: {}, TCP port: {} is open'.format(addr, port)
        else:
           print 'data for host: {}, TCP port: {} is closed'.format(addr, port)

        pings.print_stats()
        print 'avg delay={}ms'.format(pings.delay())
        print 'icmp ipid={}'.format(pings.get_header_item_list("IPID"))
        print 'tcp ipid={}'.format(tcp_id)


        if verb:
            print ''
            print "Data from last ICMP packet:"
            print pings.print_dict()

        print ''
    else:
        print 'invalid IPv4 addr'


if __name__ == '__main__':
    main()
