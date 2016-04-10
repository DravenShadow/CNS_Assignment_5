from PacketSniffer import PacketSniffer
from os import system
from easygui import msgbox
from sys import exit


def main():
    print('Welcome to the BGP Detection Program!\nWARNING: If you want BGP enabled, don\'t use this program! ')
    try:
        user_input = raw_input('Do you wish to continue? [Y/n]')
    except ValueError:
        user_input = 'Y'
    if user_input.lower() is 'n':
        exit()
    else:
        sniffer = PacketSniffer('192.168.1.7')
        sniffer.run()
        if sniffer.get_bgp_dst():
            msgbox('BGP Packet Detected.  Closing BGP port...', 'BGP Port is Open')
            system('sudo iptables -A INPUT -s 0.0.0.0 --dport 179 -j DROP')
            system('sudo iptables save')


if __name__ == '__main__':
    main()