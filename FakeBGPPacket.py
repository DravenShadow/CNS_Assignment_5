from os import system

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
    system('sudo iptables -A INPUT -s 0.0.0.0 --dport 179 -j DROP')
    system('sudo iptables save')


def main():
    """
    This is the main method
    :return:
    """
    sniffer = PacketSniffer('192.168.1.7')
    sniffer.unencrypted_comm(179)
    bgp_block()


'''
    This starts the main method
'''
if __name__ == '__main__':
    main()
