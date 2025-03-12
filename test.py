import unittest
from scapy.all import *
from scapy.layers import inet
from scapy.layers.dns import (
    DNS,
    DNSQR
)


def test_dns():
    dst_ip = "8.8.8.8"
    dst_port = 53
    fqdn = "monip.io"
    record_type = "A"

    dns_request = inet.IP(dst=dst_ip) \
              / fuzz(inet.UDP(sport=59890, dport=dst_port)) \
              / fuzz(DNS(qr=0,
                         opcode=0,
                         aa=0,
                         tc=0,
                         rd=1,
                         z=0,
                         ad=0,
                         cd=0,
                         rcode=0,
                         qd=DNSQR(
                             qname=fqdn,
                             qtype=record_type,
                             unicastresponse=0,
                             qclass='IN'
                         )))

    answer = sr1(dns_request, verbose=1)

    print(answer[DNS].summary())


if __name__ == '__main__':
    test_dns()