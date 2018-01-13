# -*- coding: utf-8 -*-
# from scapy.allでも良い
from scapy.sendrecv import sendp
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, Raw


TARGET_MAC_ADDRESS = '88:xx:xx:xx:xx:xx'

PREFIX_PAYLOAD = 'ff' * 6
BROADCAST_MAC_ADDRESS = 'FF:FF:FF:FF:FF:FF'
LIMITED_BROADCAST_IP_ADDRESS = '255.255.255.255'


def send_magic_packet():
    # マジックパケットの仕様に従い、文字列でペイロードを準備
    # https://ja.wikipedia.org/wiki/Wake-on-LAN
    str_payload = PREFIX_PAYLOAD + (TARGET_MAC_ADDRESS.replace(':', '') * 16)
    # Python2でしか動作させないので、decode('hex')を使う
    # https://stackoverflow.com/questions/443967/how-to-create-python-bytes-object-from-long-hex-string
    hex_payload = str_payload.decode('hex')

    ether_layer = Ether(dst=BROADCAST_MAC_ADDRESS)
    ip_layer = IP(dst=LIMITED_BROADCAST_IP_ADDRESS)
    udp_layer = UDP()
    raw_layer = Raw(load=hex_payload)
    magic_packet = ether_layer / ip_layer / udp_layer / raw_layer
    sendp(magic_packet)


if __name__ == '__main__':
    send_magic_packet()
