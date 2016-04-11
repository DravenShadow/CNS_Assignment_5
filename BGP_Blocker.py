from sys import exit
import iptc
from easygui import msgbox
from PacketSniffer import PacketSniffer

'''
        BGP_Blocker.py                                  Author: Rowland DePree

        A program designed to stop BGP packets from coming through once they are detected.

'''

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
            bgp_block()


'''
    This runs the main method
'''
if __name__ == '__main__':
    main()