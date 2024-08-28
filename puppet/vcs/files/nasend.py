#!/usr/bin/env python

import sys
import socket
import fcntl
import struct
import time

# /usr/include/linux/sockios.h
SIOCGIFHWADDR = 0x8927

# /usr/include/linux/if_ether.h
ETH_P_IPV6 = 0x86dd

# /usr/include/netinet/icmp6.h
ND_NEIGHBOR_ADVERT = 136
ND_OPT_TARGET_LINKADDR = 2

# NA destination address (all nodes)
ALL_NODES_IPADDRESS = 'ff02::1'
ALL_NODES_HWADDRESS = [0x33, 0x33, 0, 0, 0, 1]

MAX_HOPS = 255
NUMBER_OF_PACKETS = 5


def calc_checksum(data):
    chksum = 0

    count = len(data) // 2
    fmt = '!%sH' % count
    for word in struct.unpack(fmt, data[:count * 2]):
        chksum += word

    if len(data) > count * 2:
        # odd number of words, should never happen for ndisc na
        chksum += (ord(data[-1]) << 8)

    while chksum > 0xffff:
        chksum = (chksum >> 16) + (chksum & 0xffff)

    return ~chksum & 0xffff


def get_ipv6_pseudo_header(src_ip, dst_ip):
    '''
    pseudo header is only used for checksum calculation
    https://tools.ietf.org/html/rfc2460#section-8.1
    '''
    ipv6_pseudo_fields = [
        32,  # Payload length (32 bits) - fixed to 32 for NA
        58   # 0 (24 bits) + Next Header (8 bits) - fixed to 58
        ]
    ipv6_header = struct.pack('!LL', *ipv6_pseudo_fields)

    packed_src_ip = socket.inet_pton(socket.AF_INET6, src_ip)
    packed_dst_ip = socket.inet_pton(socket.AF_INET6, dst_ip)

    return packed_src_ip + packed_dst_ip + ipv6_header


def get_ipv6_real_header(src_ip, dst_ip):
    '''
    https://tools.ietf.org/html/rfc2460#section-3
    '''
    ipv6_fields = [
        0x60000000,  # IP version + class + flow control (32 bits)
        32,          # Payload length (16 bits) - fixed to 32 for NA
        58,          # Next Header (8 bits) - fixed to 58
        MAX_HOPS     # HOP LIMIT  (8 bits)
        ]
    ipv6_header = struct.pack('!LHBB', *ipv6_fields)

    packed_src_ip = socket.inet_pton(socket.AF_INET6, src_ip)
    packed_dst_ip = socket.inet_pton(socket.AF_INET6, dst_ip)

    return ipv6_header + packed_src_ip + packed_dst_ip


def get_ethernet_frame(src_mac, dst_mac):
    '''
    https://tools.ietf.org/html/rfc2464
    '''
    packed_dst = struct.pack('!BBBBBB', *dst_mac)
    packed_src = struct.pack('!BBBBBB', *src_mac)
    packed_type = struct.pack('!H', ETH_P_IPV6)

    return packed_dst + packed_src + packed_type


def get_mac_address(sock, iface):
    '''
    http://stackoverflow.com/a/4789267/587254
    '''

    try:
        info = fcntl.ioctl(sock.fileno(), SIOCGIFHWADDR,
                           struct.pack('256s', iface[:15]))
    except IOError as e:
        print e
        sys.exit(1)

    return [ord(c) for c in info[18:24]]


def get_mac_string(mac_bytes):
    '''
    readable format of mac address, for debugging
    '''
    return ':'.join(["%02x" % b for b in mac_bytes])


def get_icmpv6_header(sock, mac, ipaddress, checksum=0):
    '''
    https://tools.ietf.org/html/rfc4861#section-4.4
    '''
    icmp_fields = [
        ND_NEIGHBOR_ADVERT,  # icmpv6 type (8 bits)
        0,  # code (8 bits)
        checksum,  # checksum (16 bits)
        0x20000000  # flags (override on) + reserved (32 bits)
        ]
    icmp_header = struct.pack('!BBHL', *icmp_fields)

    target_ip = socket.inet_pton(socket.AF_INET6, ipaddress)

    options = struct.pack('!BBBBBBBB', ND_OPT_TARGET_LINKADDR, 1, *mac)

    return icmp_header + target_ip + options


def send_unsolicited_na(sock, iface, ipaddress):
    '''
    assemble and send the packet
    '''

    mac = get_mac_address(sock, iface)
    print "mac: " + get_mac_string(mac)

    icmpv6_payload = get_icmpv6_header(sock, mac, ipaddress)

    # checksum is automatically updated by kernel for icmpv6 packets
    # however better include it here just in case tx offload is switched off
    ipv6_pseudo_header = get_ipv6_pseudo_header(ipaddress, ALL_NODES_IPADDRESS)
    checksum = calc_checksum(ipv6_pseudo_header + icmpv6_payload)
    icmpv6_payload = get_icmpv6_header(sock, mac, ipaddress, checksum)

    ethernet_frame = get_ethernet_frame(mac, ALL_NODES_HWADDRESS)
    ipv6_real_header = get_ipv6_real_header(ipaddress, ALL_NODES_IPADDRESS)
    packet = ethernet_frame + ipv6_real_header + icmpv6_payload

    try:
        for _ in range(NUMBER_OF_PACKETS):
            sock.send(packet)
            time.sleep(0.0001)  # probably unnecessary
    except Exception as e:
        print e


def main():
    args = sys.argv
    if len(args) != 3:
        print "Usage: nasend-eth.py <device> <ipv6 address>"
        return 1

    iface = args[1]
    ipaddress = args[2]

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((iface, 0))
    except Exception as e:
        print e
        return 1

    send_unsolicited_na(sock, iface, ipaddress)
    sock.close()

if __name__ == '__main__':
    sys.exit(main())
