"""
A custom data type that will store lists of pings from
an ICMP ping session, and process data.
"""

import os
import select
import struct
import time
import socket
from libs.helpers import get_headers
from libs.helpers import make_checksum

class ICMPSession(object):
    """
    a custom class that takes ICMPSession
    packets and breaks them down into
    dictionary files, also holds delay values
    """

    def __init__(self, ip):
        """
        Init With IP.
        """
        self.remote_ip = ip
        self.packet_data_list = []
        self.delay_list = []
        self.sent_count = 0
        self.timeout_count = 0
        self.receive_count = 0

    def __len__(self):
        """
        This makes the class complatable with len()
        """

        return len(self.packet_data_list)

    def __getitem__(self, key):
        """
        Enables use of the instance[key] usage
        """

        if not isinstance(key, int):
            raise TypeError

        return self.packet_data_list[key]


    def __setitem__(self, key, value):
        """
        Enables use of the instance[key] usage
        """

        #check for valid input
        if not isinstance(value, str):
            raise TypeError

        if not isinstance(key, int):
            raise TypeError

        self.packet_data_list[key] = process_packet_list(value)


    def start_ping(self, p_count):
        """
        The main method for our Ping. makes the socket, and gets the data.
        """
        addr = self.remote_ip
        system_id = os.getpid()  & 0xFFFF

        #Exception if script is not run as root
        for i in range(0, p_count):
            try:
                #make a BSD socket, using Py's wrapper on the Socket() call.
                current_socket = socket.socket(socket.AF_INET,
                                            socket.SOCK_RAW,
                                            socket.IPPROTO_ICMP)
            except socket.error as err:
                if err.errno == 1:
                    raise socket.error(''.join((err.args[1], #err
                        "Process must be run as root.")))  #msg
                raise

            #send packet
            send_time = send_packet(current_socket, addr)

            if send_time == None:
                #error from send method
                return False

            self.sent_count += 1

            receive_time, raw_packet = receive_packet(current_socket, system_id)
            current_socket.close()

            if receive_time:
                self.receive_count += 1
                delay = (receive_time - send_time) * 1000.0
                self.append_packet(raw_packet)
                self.append_delay(delay)
            else:
                self.timeout_count += 1

        if self.receive_count == 0:
            return  False
        else:
            return True


    def append_packet(self, packet):
        """
        adds a new packet to the list
        input is a string taken fron socket.recvfrom()
        """

        temp_dict = process_packet_list(packet)
        self.packet_data_list.append(temp_dict)

    def get_packet_list(self):
        """
        returns the list of dictionaries
        """
        return self.packet_data_list

    def print_dict(self):
        """
        Takes + prints data from last packet in the list
        """
        current_packet = self.packet_data_list[-1]

        print'IPv{}'.format(current_packet['version']),
        print'len={}'.format(current_packet['length']),
        print'IPID={}'.format(current_packet['IPID']),
        print'proto={}'.format(current_packet['protocol'])
        print'IP={}'.format(current_packet['IP'])

    def print_stats(self):
        """
        Prints data on packet transmission
        """
        print "{} packets sent, {} packets received, {} timeouts".format(self.sent_count,
                                                                self.receive_count,
                                                                self.timeout_count)


    def append_delay(self, delay):
        """
        Adds a new delay item to the instance list
        """
        self.delay_list.append(delay)


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


    def delay(self):
        """
        returns an average of all the delay times
        """

        if len(self.delay_list) == 0:
            return 0

        total_delay = sum(self.delay_list)/len(self.delay_list)

        return round(total_delay, 3)


#end of dedicated class methods, begin generic ICMP tools
def process_packet_list(data):
    """
    This will take a raw list of items
    that we receve and sort/organize,
    and parse the ICMP packet
    """
    temp_dict = {}

    ip_header, iph_length = get_headers(data)

    #ICMP header data unused for now
    icmp_header_struct = data[iph_length:iph_length+12]
    icmp_header = struct.unpack('!BBHHH4s', icmp_header_struct)


    temp_dict["version"] = (ip_header[0] >> 4)
    temp_dict["length"] = ip_header[2]
    temp_dict["IPID"] = ip_header[3]
    temp_dict["protocol"] = ip_header[6]
    temp_dict["IP"] = socket.inet_ntoa(ip_header[9])
    temp_dict["src_ip"] = socket.inet_ntoa(ip_header[8])


    return temp_dict


def list_to_int(bit_list):
    """
    Takes a list of binary numbers and converts it to base 10
    """

    header = '0b'

    for  bit in bit_list:
        header += str(bit)

    return int(header, 2)


def to_bits(bit_str):
    """
    converts a string from the raw socket input, returns a list of  bits
    """
    result = []
    for digit in bit_str:
        bits = bin(ord(digit))[2:]
        bits = '00000000'[len(bits):] + bits
        result. extend([int(b) for b in bits])
    return result

def send_packet(current_socket, addr):
    """
    This will send one ICMP echo request packet to our given host
    """
    packet_size = 55
    system_id = os.getpid() & 0xFFFF #prevents 16 bit overflow
    seq_num = 0
    checksum = 0
    #make a dummy header for calc. of checksum
    header = struct.pack("!BBHHH", # 2 Unsigned Chars, 3 Unsigned Shorts
                         8, #control code for an echo request
                         0, #ICMP subtype code
                         checksum, #checksum. Is = 0 for dummy header
                         system_id, #identifies the packet
                         seq_num) #ID's sequence of ICMP packets

    #still  undetstanding how this next part works, details incoming...
    pad_bytes = []
    start_val = 0x42 #66 in base 10

    #creates a list of ascending numbers
    for i in range(start_val, (start_val+packet_size)):
        pad_bytes += [(i & 0xff)] # 0xFF is largest 8 bit value
    #dummy data for ICMP packet
    data = bytes(pad_bytes) #convert data to string representation

    checksum = make_checksum(header + data)

    #contruct a new header with the proper checksum
    header = struct.pack("!BBHHH", 8, 0, checksum, system_id, seq_num)

    packet = header + data

    time_at_send = time.time()

    try:
        current_socket.sendto(packet, (addr, 1))
    except socket.error:
        print"general socket error"
        current_socket.close()
        return

    return time_at_send

def receive_packet(current_socket, system_id):
    """
    we wait and receive the packet from the packet from the host
    """

    timeout = 1.0

    while True: #loop untill something happens, like a timeout. Or Packet.
        #will check if our socket is ready to be read from
        input_ready, dummyoutput, dummyexcept = select.select([current_socket], [], [], timeout)


        if input_ready == []: #input not ready,  thus no data has been receved
           # print("Timeout")
            return None, 0

        wait_time = time.time()

        #socket is ready, get packet from the socket
        packet_data, address = current_socket.recvfrom(2048) #2048 = max buffer

        #get the packet id, two bytes in size
        ICMPID = packet_data[24:26]
        #convert the data from string data to int
        ICMPID_int = list_to_int(to_bits(ICMPID))

        #This is our packet, return data
        if ICMPID_int == system_id:
            return wait_time, packet_data
        else:
            return None, 0
