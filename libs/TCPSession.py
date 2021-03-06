"""
OO method of getting data From TCP scan.
"""
import sys
import select
import struct
import socket
import random
from libs.helpers import get_headers
from libs.ICMPSession import ICMPSession
from libs.helpers import make_checksum

class TCPSession(object):
    """
    Custom class that can be used for TCP port scanning
    """

    def __init__(self, ip_addr):
        """
        Init class instance
        """
        self.remote_ip = ip_addr
        self.packet_data_list = []
        self.sent_count = 0
        self.receive_count = 0
        self.timeout_count = 0

        #This is our hackey way of getting our interface IP
        #useful for systems with more than one NIC/IP
        pings = ICMPSession(ip_addr)
        reach = pings.start_ping(2)

        if not reach:
            print "Error pinging host"
            sys.exit()

        ping_data = pings.get_packet_list()
        ping_packet = ping_data[-1]
        interface_ip = ping_packet['IP']

        self.nic_ip = interface_ip

    def __len__(self):
        """
        Make compatable with len()
        """
        return len(self.packet_data_list)


    def __getitem__(self, key):
        """
        Enables use of the instance[key] usage
        """

        if not isinstance(key, int):
            raise TypeError

        return self.packet_data_list[key]



    def print_dict(self):
        """
        prints the dictionary
        """
        print self.packet_data_list


    def get_packet_list(self):
        """
        returns the list of dictionaries
        """
        return self.packet_data_list

    def get_header_item_list(self, key):
        """
        takes a key item, and returns a list
        of all the instances of that header item across
        all of the packets
        """

        if not isinstance(key, str):
            raise TypeError

        item_list = []

        for packet in self.packet_data_list:
            item_list.append(packet[key])

        return item_list


    def scan_addr_at_port(self, port_array):
        """
        takes an array of ports, or a single port, and pings it
        """

        if type(port_array) is list:
            for port in port_array:
                final_packet = self.construct_packet(port)
                self.send_packet(final_packet)
                self.listen_packet()
        elif type(port_array) is int:
            final_packet = self.construct_packet(port_array)
            self.send_packet(final_packet)
            self.listen_packet()
        else:
            print type(port_array)
            raise TypeError

    def construct_packet(self, dest_port):
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
        ip_saddr = socket.inet_aton(self.nic_ip)
        ip_daddr = socket.inet_aton(self.remote_ip)

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
        tcp_seq = random.randint(100, 700) #random seq between 100 & 700
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

        source_address = socket.inet_aton(self.nic_ip)
        dest_address = socket.inet_aton(self.remote_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)

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


    def send_packet(self, packet):
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
            current_socket.sendto(packet, (self.remote_ip, 0))
        except socket.error:
            print"general socket error"
            current_socket.close()
            raise


    def listen_packet(self):
        """
        Listens on the socket
        and prints the packet it gets
        """
        temp_dict = {}
        timeout = 1.0
        #This is our listening socket
        #for reasons unknown to me, IPPROTO_TCP must be passed for
        #the packet sniffing socket, sending packet uses IPPROTO_RAW
        try:
            current_socket = socket.socket(socket.AF_INET,
                            socket.SOCK_RAW,
                            socket.IPPROTO_TCP)
        except socket.error, msg:
            print str(msg[0])

        #listen
        input_ready, dummyoutput, dummyexcept = select.select([current_socket], [], [], timeout)

        #timeout
        if input_ready == []:
            temp_dict["IPID"] = 0
            temp_dict["status"] = "filtered"
            temp_dict["src_pt"] = 0
            temp_dict["dest_pt"] = 0
            temp_dict["ack"] = 0
            self.packet_data_list.append(temp_dict)
            return

        #no timeout
        data_back = current_socket.recvfrom(65565)
        current_socket.close()

        packet = data_back[0]

        self.process_packet(packet)


    def process_packet(self, packet):
        """
        unpack and process data we get back, insert into dictionaries
        """
        temp_dict = {}

        ip_header, iph_length = get_headers(packet)

        #tcp header
        tcp_header = packet[iph_length:iph_length+20]

        #now unpack
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        return_flags = tcph[5]

        port_status = "open"
        #flags are RST, or ACK/RST
        if return_flags == 20 or return_flags == 4:
            port_status = "closed"

        #pack data
        temp_dict["ack"] = acknowledgement
        temp_dict["IPID"] = ip_header[3]
        temp_dict["status"] = port_status
        temp_dict["src_pt"] = source_port
        temp_dict["dest_pt"] = dest_port

        self.packet_data_list.append(temp_dict)
