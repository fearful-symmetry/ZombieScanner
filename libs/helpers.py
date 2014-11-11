"""
A set of helper methods for various network parsing functions
"""
import sys
import struct
import socket

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


def get_headers(data):
    """
    takes the raw socket data as input, returns the IP header
    and length of the IP header from IPH field
    """

    ip_header_raw = data[0:20]

    ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header_raw)
    version_ihl = ip_header[0]
    #second half, IHL
    ihl = version_ihl & 0xF
    #length of packet
    iph_length = ihl * 4

    return ip_header, iph_length
