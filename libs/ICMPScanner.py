"""
A network tool that collects header data
for idle port scans
"""
import sys
import os
import select
import socket
import struct
import time
from libs.ICMPSession import list_to_int
from libs.ICMPSession import to_bits
from libs.ICMPSession import ICMPSession



def make_checksum(checksum_string):
    """
    makes an ICMP checksum
    converts the string to 16-bit int
    ads the values and appends 1's compliment
    """
    count_to = (int(len(checksum_string) / 2)) * 2 #248
    sum_of_int = 0
    count = 0

    #handle bytes in pairs
    low_byte = 0
    high_byte = 0

    #iterate through the string, byte by byte
    while count < count_to:
        if sys.byteorder == "little": #is the system byte order little-endian?
            low_byte = checksum_string[count]
            high_byte = checksum_string[count + 1]
        else:
            low_byte = checksum_string[count + 1]
            high_byte = checksum_string[count]

        sum_of_int = sum_of_int + (ord(high_byte) * 256 + ord(low_byte))
        count += 2

    #handle any leftover bytes
    if count_to < len(checksum_string):
        low_byte = checksum_string[len(checksum_string)-1]
        sum_of_int += ord(low_byte)

    sum_of_int &= 0xffffffff #trunicate sum to 32 bits

    #here we take the 1st and 2nd 16 bit ints and add them
    sum_of_int = ((sum_of_int >> 16) +
                (sum_of_int & 0xffff))

    sum_of_int += (sum_of_int >> 16)
    #get one's compliment
    answer = ~sum_of_int & 0xffff
    #convert to network byte order
    answer = socket.htons(answer)

    return answer


def start_ping(addr, p_count):
    """
    The main method for our Ping. makes the socket, and gets the data.
    """
    sent_count = 0
    receive_count = 0
    timeout_count = 0
    system_id = os.getpid()  & 0xFFFF
    packet_list = []
    session_pings = ICMPSession()

    #try/catch block. Exception if script is not run as root
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
            return None, None, None, None #error from send method

        sent_count += 1

        receive_time, raw_packet = receive_packet(current_socket, system_id)
        current_socket.close()

        if receive_time:
            receive_count += 1
            packet_list.append(raw_packet)
            delay = (receive_time - send_time) * 1000.0

            session_pings.append_packet(raw_packet)
            session_pings.append_delay(delay)
        else:
            timeout_count += 1

    if receive_count == 0:
        return  None, None, None, None
    else:
        return session_pings, sent_count, receive_count, timeout_count



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


def check_IPv4(addr):
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


def icmp_ipid(dest, verb):
    """
    our main function that starts the scan
    """
    if check_IPv4(dest):
        #Get list of raw data  packets
        (session_data,
        sent_count,
        receive_count,
        timeout_count) = start_ping(dest, 5)
        if session_data:

            print "{} packets sent, {} packets receved, {} timeouts".format(sent_count,
                                                            receive_count,
                                                            timeout_count)
            print "The average delay time for this host is: {} ms".format(session_data.delay())

            if verb:
                print "Data from last ICMP packet:"
                print session_data.print_dict()

            return session_data.get_header_item_list("IPID")

        else:
            print"Error: host could not be reached"

    else:
        print"Error: invalid IPv4 address"

