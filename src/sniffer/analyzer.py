from datetime import datetime
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

from .models import PacketInfo


class PacketAnalyzer:
    """Analyze Scapy packets and extract useful information."""

    PAYLOAD_PREVIEW_LENGTH = 64

    def analyze(self, packet: Packet, number: int) -> PacketInfo:
        """Convert a Scapy packet into structured PacketInfo."""

        source_ip: Optional[str] = None
        destination_ip: Optional[str] = None

        protocol = "OTHER"
        source_port: Optional[int] = None
        destination_port: Optional[int] = None

        # IPv4
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        # IPv6
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        # ARP
        if ARP in packet:
            protocol = "ARP"

            source_ip = packet[ARP].psrc
            destination_ip = packet[ARP].pdst

        # TCP
        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        # UDP
        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # ICMP
        elif ICMP in packet:
            protocol = "ICMP"

        payload_preview, payload_size = self._extract_payload(packet)

        return PacketInfo(
            number=number,
            timestamp=datetime.now(),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_size=len(packet),
            payload_preview=payload_preview,
            payload_size=payload_size,
        )

    def _extract_payload(self, packet: Packet) -> tuple[str, int]:
        """Extract a limited and safe application payload preview."""

        try:
            if Raw not in packet:
                return "", 0

            raw_bytes = bytes(packet[Raw].load)

        except (TypeError, ValueError, AttributeError):
            return "", 0

        if not raw_bytes:
            return "", 0

        payload_size = len(raw_bytes)
        preview = raw_bytes[: self.PAYLOAD_PREVIEW_LENGTH]

        printable = "".join(
            chr(byte) if 32 <= byte <= 126 else "."
            for byte in preview
        )

        if payload_size > self.PAYLOAD_PREVIEW_LENGTH:
            printable += "..."

        return printable, payload_size