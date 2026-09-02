from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .models import PacketInfo


class PacketDisplay:
    """Render packet information and statistics in the terminal."""

    def __init__(self) -> None:
        self.console = Console()
        self.protocol_counter: Counter[str] = Counter()
        self.total_bytes = 0

    def show_banner(self) -> None:
        """Display the application banner."""

        banner = """
╔══════════════════════════════════════════════════════════╗
║              CODEALPHA NETWORK SNIFFER                  ║
║                 Basic Packet Analyzer                   ║
╚══════════════════════════════════════════════════════════╝
"""

        self.console.print(banner)

    def show_status(
        self,
        interface: str | None,
        count: int,
        protocol_filter: str,
    ) -> None:
        """Display current capture configuration."""

        interface_name = interface or "Default Interface"
        packet_limit = count if count > 0 else "Unlimited"

        status = (
            f"[bold]Interface:[/bold] {interface_name}\n"
            f"[bold]Packet Limit:[/bold] {packet_limit}\n"
            f"[bold]Protocol Filter:[/bold] {protocol_filter}\n"
            f"[bold]Status:[/bold] Capturing..."
        )

        self.console.print(
            Panel(
                status,
                title="Capture Configuration",
                border_style="blue",
            )
        )

    def show_packet(self, packet: PacketInfo) -> None:
        """Display one analyzed packet."""

        self.protocol_counter[packet.protocol] += 1
        self.total_bytes += packet.packet_size

        table = Table(
            title=f"Packet #{packet.number:03d}",
            show_header=False,
            expand=True,
        )

        table.add_row(
            "Timestamp",
            packet.timestamp.strftime("%H:%M:%S"),
        )
        table.add_row("Source IP", packet.source_ip or "N/A")
        table.add_row(
            "Destination IP",
            packet.destination_ip or "N/A",
        )
        table.add_row("Connection", packet.connection)
        table.add_row("Protocol", packet.protocol)

        table.add_row(
            "Source Port",
            str(packet.source_port)
            if packet.source_port is not None
            else "N/A",
        )

        table.add_row(
            "Destination Port",
            str(packet.destination_port)
            if packet.destination_port is not None
            else "N/A",
        )

        table.add_row(
            "Packet Size",
            f"{packet.packet_size} bytes",
        )

        table.add_row(
            "Payload Size",
            f"{packet.payload_size} bytes",
        )

        table.add_row(
            "Payload Preview",
            packet.payload_preview or "No payload",
        )

        self.console.print(table)
        self.console.print()

    def show_summary(self) -> None:
        """Display capture statistics."""

        total_packets = sum(self.protocol_counter.values())

        table = Table(title="Capture Summary")

        table.add_column("Metric")
        table.add_column("Value")

        table.add_row("Total Packets", str(total_packets))
        table.add_row("Total Bytes", f"{self.total_bytes:,}")

        for protocol, count in sorted(self.protocol_counter.items()):
            table.add_row(
                f"{protocol} Packets",
                str(count),
            )

        self.console.print()
        self.console.print(table)