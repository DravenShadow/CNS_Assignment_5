"""
    Author: Rowland DePree              sniffer.py
    This is a class designed as an packet sniffer.  It will decode all incoming traffic as well as alert the user if
    the packet is using an port that is marked as dangerous.  The original idea for this code came from Black Hat Python
    by Justin Seitiz.
"""
import ctypes
import winsound
from os import name
from socket import IPPROTO_IP, SOCK_RAW, RCVALL_ON, SIO_RCVALL, IPPROTO_ICMP, RCVALL_OFF, socket, AF_INET, IP_HDRINCL

from easygui import msgbox

from IP import IP
from TCP import TCP


class PacketSniffer:
    def __init__(self, host):
        self.host = host

    def get_bgp_dst(self):
        return self.bgp_dst

    def unencrypted_comm(self, port_num):
        """
        A method used to check if the port is unencrypted and if so alert the user
        :param port_num:
        :return:
        """
        if port_num == 179:
            freq = 2500
            dur = 1000
            winsound.Beep(freq, dur)
            msgbox("Incoming Packet on Port %s \nBGP Packet...." % port_num,
                   "Unauthorized BGP Packet")
            return True
        else:
            return False

    def run(self):
        """
        Main part of the program.  This is where it reads in and decodes all packet traffic
        :return:
        """
        if name == "nt":
            socket_protocol = IPPROTO_IP
        else:
            socket_protocol = IPPROTO_ICMP

        sniffer = socket(AF_INET, SOCK_RAW, socket_protocol)

        sniffer.bind((self.host, 0))

        sniffer.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

        if name == "nt":
            sniffer.ioctl(SIO_RCVALL, RCVALL_ON)
        try:
            while True:
                raw_buffer = sniffer.recvfrom(65565)[0]

                ip_header = IP(raw_buffer[0:20])

                print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

                if ip_header.protocol == "TCP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + ctypes.sizeof(TCP)]

                    tcp_header = TCP(buf)

                    bgp_dstport = self.unencrypted_comm(tcp_header.dstport)
                    if bgp_dstport:
                        self.bgp_dst = True

                    print("TCP -> Source Port: %d Dest Port: %d" % (tcp_header.srcport, tcp_header.dstport))
        except KeyboardInterrupt:
            if name == "nt":
                sniffer.ioctl(SIO_RCVALL, RCVALL_OFF)
