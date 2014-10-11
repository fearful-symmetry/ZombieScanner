"""
Prototype code to perform a partial syn scan using raw sockets
"""
import sys
import argparse
import socket
import struct
import random
from ICMPSession import make_checksum
from ICMPSession import *


def construct_packet(dest_port, ip_addr):
    """
    Construct our raw TCP packet
    """
    ip_ver = 4
    ip_ihl = 5
    ip_dscp = 0
    ip_total_length = 0
    ipid = 54321
    ip_frag_offset = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0 #0 for our dummy header

    #This is our hackey way of getting our interface IP
    #useful for systems with more than one NIC/IP
    pings = ICMPSession(ip_addr)
    reach = pings.start_ping(2)


    if not reach:
        print "Host could not be reached"
        sys.exit()

    ping_data = pings.get_packet_list()
    ping_packet = ping_data[-1]
    interface_ip = ping_packet['src_ip']

    # print "Done ping: {}".format(interface_ip)

    ip_saddr = socket.inet_aton(interface_ip)
    ip_daddr = socket.inet_aton(ip_addr)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    #construct the header struct
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_dscp,
                            ip_total_length,
                            ipid,
                            ip_frag_offset,
                            ip_ttl, ip_proto,
                            ip_check,
                            ip_saddr,
                            ip_daddr)



    tcp_source = 64703 #source port
    tcp_dest = dest_port
    tcp_seq = random.randint(100,700)
    tcp_ack_seq = 0
    tcp_doff = 5
    #flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    #add all our bit flags
    tcp_flags = (tcp_fin +
                (tcp_syn << 1) +
                (tcp_rst << 2) +
                (tcp_psh <<3) +
                (tcp_ack << 4) +
                (tcp_urg << 5))

    #pack our TCP header
    tcp_header = struct.pack('!HHLLBBHHH',
                            tcp_source,
                            tcp_dest,
                            tcp_seq,
                            tcp_ack_seq,
                            tcp_offset_res,
                            tcp_flags,
                            tcp_window,
                            tcp_check,
                            tcp_urg_ptr)

    source_address = socket.inet_aton(interface_ip)
    dest_address = socket.inet_aton(ip_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)# + len(packet_data)

    #psudo header used in checksum calculation
    dummy = struct.pack('!4s4sBBH',
                        source_address,
                        dest_address,
                        placeholder,
                        protocol,
                        tcp_length)

    dummy = dummy + tcp_header

    tcp_check = make_checksum(dummy)

    #Thus begins the actual TCP header with the complete checksum
    tcp_header = struct.pack('!HHLLBBH',
                            tcp_source,
                            tcp_dest,
                            tcp_seq,
                            tcp_ack_seq,
                            tcp_offset_res,
                            tcp_flags,
                            tcp_window) + (struct.pack('!H', tcp_check) +
                             struct.pack('!H', tcp_urg_ptr))

    #construct final packet
    f_packet = ip_header + tcp_header #+ packet_data
    return f_packet


def send_packet(packet, ip_addr):
    """
    Sends the packet using raw socket
    """

    try:
    #raw socket for send
        current_socket = socket.socket(socket.AF_INET,
                                        socket.SOCK_RAW,
                                        socket.IPPROTO_RAW)

    except socket.error as err:
        #error, not run as root
        if err.errno == 1:
            raise socket.error(''.join((err.args[1], #err
                "Process must be run as root.")))  #msg
        raise


    try:
        current_socket.sendto(packet, (ip_addr, 0))
    except socket.error:
        print"general socket error"
        current_socket.close()
        raise


def listen_packet():
    """
    Listens on the socket
    and prints the packet it gets
    """
    timeout = 1.0
    #This is our listening socket
    try:
        current_socket = socket.socket(socket.AF_INET,
                        socket.SOCK_RAW,
                        socket.IPPROTO_TCP)
    except socket.error, msg:
        print str(msg[0])

    input_ready, dummyoutput, dummyexcept = select.select([current_socket], [], [], timeout)

    if input_ready == []:
        return None, None

    data_back = current_socket.recvfrom(65565)
    current_socket.close()

    packet = data_back[0]

    #header from packet
    ip_header = packet[0:20]

    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    #version/IHL = first byte
    version_ihl = iph[0]
    #second half, IHL
    ihl = version_ihl & 0xF
    #length of packet
    iph_length = ihl * 4

    #tcp header
    tcp_header = packet[iph_length:iph_length+20]

    #now unpack
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    return_flags = tcph[5]

    port_status = True;
    if return_flags == 20 or return_flags == 4:
        port_status = False

    return iph[3], port_status




def scan_addr(addr, port):
    """
    start our tcp scan from here
    """
    tcp_id_list = []
    port_open = False
    for i in range(0,5):
        final_packet = construct_packet(port, addr)
        send_packet(final_packet, addr)
        ipid, port_status = listen_packet()
        # if port_status == None:
#             return None, None
        tcp_id_list.append(ipid)
        port_open = port_status

    return tcp_id_list, port_open
    # final_packet = construct_packet(port, addr)
    # send_packet(final_packet, addr)
    # return listen_packet()
