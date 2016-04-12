import os

import iptc
from easygui import msgbox

from PacketSniffer import PacketSniffer

"""
        FakeBGPPacket.py                                    Author: Rowland DePree


        This is a program designed to demonstrate what happens if a packet using the BGP TCP port is found.

"""

def bgp_block():
    """
    Uses IPTables to block BGP packets and also alerts the user of an packet using the BGP port
    :return:
    """
    msgbox('BGP Packet Detected.  Closing BGP port...', 'BGP Port is Open')
    rule = iptc.Rule()
    rule.protocol = 'tcp'
    match = rule.create_match('tcp')
    match.dport = '179'
    target = iptc.Target(rule, "DROP")
    rule.target = target
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

def main():
    """
    This is the main method
    :return:
    """
    if os.name is 'posix':
        sniffer = PacketSniffer('192.168.1.7')
        sniffer.unencrypted_comm(179)
        bgp_block()
        exit()
    else:
        print('INCOMPATIBLE OPERATING SYSTEM!\nPLEASE USE AN LINUX OPERATION SYSTEM!')
        exit()


'''
    This starts the main method
'''
if __name__ == '__main__':
    main()
