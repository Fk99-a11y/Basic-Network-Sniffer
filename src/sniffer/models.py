from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class PacketInfo:
    """Structured information extracted from a network packet."""

    number: int
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: str = "OTHER"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_size: int = 0
    payload_preview: str = ""
    payload_size: int = 0

    @property
    def connection(self) -> str:
        """Return a readable source-to-destination connection."""

        if not self.source_ip or not self.destination_ip:
            return "N/A"

        source = self.source_ip
        destination = self.destination_ip

        if self.source_port is not None:
            source = f"{source}:{self.source_port}"

        if self.destination_port is not None:
            destination = f"{destination}:{self.destination_port}"

        return f"{source} → {destination}"