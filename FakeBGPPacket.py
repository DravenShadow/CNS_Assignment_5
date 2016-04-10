from os import system

from easygui import msgbox

from PacketSniffer import PacketSniffer


def bgp_block():
    msgbox('BGP Packet Detected.  Closing BGP port...', 'BGP Port is Open')
    system('sudo iptables -A INPUT -s 0.0.0.0 --dport 179 -j DROP')
    system('sudo iptables save')


def main():
    sniffer = PacketSniffer('192.168.1.7')
    sniffer.unencrypted_comm(179)
    bgp_block()


if __name__ == '__main__':
    main()
