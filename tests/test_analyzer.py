from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Raw

from src.sniffer.analyzer import PacketAnalyzer


def test_tcp_packet_analysis():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=50000, dport=443)
        / Raw(load=b"test payload")
    )

    result = PacketAnalyzer().analyze(packet, 1)

    assert result.protocol == "TCP"
    assert result.source_ip == "192.168.1.10"
    assert result.destination_ip == "8.8.8.8"
    assert result.source_port == 50000
    assert result.destination_port == 443
    assert result.packet_size > 0
    assert result.payload_size > 0


def test_udp_packet_analysis():
    packet = (
        IP(src="192.168.1.20", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
    )

    result = PacketAnalyzer().analyze(packet, 1)

    assert result.protocol == "UDP"
    assert result.source_port == 53000
    assert result.destination_port == 53


def test_icmp_packet_analysis():
    packet = (
        IP(src="192.168.1.10", dst="8.8.8.8")
        / ICMP()
    )

    result = PacketAnalyzer().analyze(packet, 1)

    assert result.protocol == "ICMP"


def test_arp_packet_analysis():
    packet = ARP(
        psrc="192.168.1.10",
        pdst="192.168.1.1",
    )

    result = PacketAnalyzer().analyze(packet, 1)

    assert result.protocol == "ARP"
    assert result.source_ip == "192.168.1.10"
    assert result.destination_ip == "192.168.1.1"


def test_payload_preview_is_limited():
    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=1234, dport=80)
        / Raw(load=b"A" * 200)
    )

    result = PacketAnalyzer().analyze(packet, 1)

    assert result.payload_size > 64
    assert len(result.payload_preview) <= 67