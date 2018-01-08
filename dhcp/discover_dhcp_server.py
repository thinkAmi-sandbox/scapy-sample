# -*- coding: utf-8 -*-
from scapy.config import conf
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp
from scapy.utils import mac2str

DHCP_CLIENT_MAC_ADDRESS = '00:00:00:00:00:04'
BROADCAST_MAC_ADDRESS = 'FF:FF:FF:FF:FF:FF'

LIMITED_BROADCAST_IP_ADDRESS = '255.255.255.255'
DHCP_DISCOVER_HOST_IP_ADDRESS = '0.0.0.0'

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

USB_INTERFACE_NAME = 'en4'


def discover():
    ether_layer = Ether(
        src=DHCP_CLIENT_MAC_ADDRESS,
        dst=BROADCAST_MAC_ADDRESS,
    )

    ip_layer = IP(
        src=DHCP_DISCOVER_HOST_IP_ADDRESS,
        dst=LIMITED_BROADCAST_IP_ADDRESS,
    )

    udp_layer = UDP(
        sport=DHCP_CLIENT_PORT,
        dport=DHCP_SERVER_PORT,
    )

    # BOOTPの引数chaddrについて：
    # Scapyを使った他の実装を見たところ
    # (https://github.com/david415/dhcptakeover/blob/master/dhcptakeover.py)、
    # scapy.all.get_if_raw_hwaddr()を使っていた
    # scapy.all.get_if_raw_hwaddr()の中で `mac = mac2str(str(link_addr))` しており
    # mac2str()関数にて、規則に従いMACアドレスを文字列化してた
    # コメントに「dumbnet module」とあったので、使用モジュールの関係上、このロジックとなっているのかもしれない
    chaddr = mac2str(DHCP_CLIENT_MAC_ADDRESS)
    # なお、単にMACアドレスそのものを渡してもOKだが、その場合には同一のDHCPサーバから複数レスポンスが返ってくる
    # chaddr = DHCP_CLIENT_MAC_ADDRESS
    bootp_layer = BOOTP(chaddr=chaddr)

    dhcp_layer = DHCP(options=[('message-type', 'discover'), 'end'])

    discover_packet = ether_layer / ip_layer / udp_layer / bootp_layer / dhcp_layer

    # 作成したパケットを念のため確認
    discover_packet.show()

    # Scapyのドキュメント通りに設定して送信
    # http://scapy.readthedocs.io/en/latest/usage.html#identifying-rogue-dhcp-servers-on-your-lan
    conf.checkIPaddr = False
    answers, _ = srp(discover_packet, iface=USB_INTERFACE_NAME, multi=True)

    for send_packet, recv_packet in answers:
        print 'DHCP Server - MAC: {}, IP: {}'.format(
            recv_packet[Ether].src, recv_packet[IP].src)


if __name__ == '__main__':
    discover()
