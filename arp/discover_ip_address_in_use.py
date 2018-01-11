# -*- coding: utf-8 -*-
from datetime import datetime
from scapy.layers.l2 import ARP, arping


def discover():
    ip = '192.168.10.*'
    print 'start: {}'.format(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
    answers, _ = arping(ip, timeout=1, verbose=0)

    for send_packet, recieve_packet in answers:
        print 'MAC Address: {}, IP Address: {}'.format(
            recieve_packet[ARP].hwsrc,  # MACアドレス
            recieve_packet[ARP].psrc,   # IPアドレス
        )
    print 'end  : {}'.format(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))


if __name__ == '__main__':
    discover()
