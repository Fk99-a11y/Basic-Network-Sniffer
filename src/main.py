
import argparse
import sys
from typing import Optional

from scapy.all import get_if_list
from scapy.packet import Packet

from sniffer.analyzer import PacketAnalyzer
from sniffer.capture import PacketCapture
from sniffer.display import PacketDisplay


SUPPORTED_PROTOCOLS = {
    "ALL",
    "TCP",
    "UDP",
    "ICMP",
    "ARP",
    "OTHER",
}


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "CodeAlpha Basic Network Sniffer - "
            "Capture and analyze network packets."
        )
    )

    parser.add_argument(
        "-i",
        "--interface",
        help=(
            "Network interface to capture packets from. "
            "Use --list-interfaces to view available interfaces."
        ),
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of matching packets to capture. 0 means unlimited.",
    )

    parser.add_argument(
        "-p",
        "--protocol",
        default="ALL",
        type=str.upper,
        choices=sorted(SUPPORTED_PROTOCOLS),
        help="Protocol filter.",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="Capture timeout in seconds.",
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display available interfaces and exit.",
    )

    return parser.parse_args()


def list_interfaces() -> None:
    """Display available network interfaces."""

    print("\nAvailable network interfaces:\n")

    try:
        interfaces = get_if_list()

        for index, interface in enumerate(interfaces, start=1):
            print(f"{index}. {interface}")

    except Exception as exc:
        print(f"Unable to retrieve interfaces: {exc}")


def main() -> int:
    """Application entry point."""

    args = parse_arguments()

    if args.list_interfaces:
        list_interfaces()
        return 0

    if args.count < 0:
        print("Error: packet count cannot be negative.")
        return 1

    if args.timeout is not None and args.timeout <= 0:
        print("Error: timeout must be greater than 0.")
        return 1

    display = PacketDisplay()
    analyzer = PacketAnalyzer()

    display.show_banner()

    display.show_status(
        interface=args.interface,
        count=args.count,
        protocol_filter=args.protocol,
    )

    packet_number = 0

    def process_packet(packet: Packet) -> Optional[Packet]:
        nonlocal packet_number

        analyzed = analyzer.analyze(
            packet,
            packet_number + 1,
        )

        packet_number += 1
        analyzed.number = packet_number

        display.show_packet(analyzed)

        return packet

    try:
        capture = PacketCapture(
            interface=args.interface,
            packet_count=args.count,
            timeout=args.timeout,
            protocol_filter=args.protocol,
        )

        capture.start(process_packet)

    except KeyboardInterrupt:
        display.console.print(
            "\n[yellow][!] Capture stopped by user.[/yellow]"
        )

    except PermissionError:
        display.console.print(
            "\n[red][!] Permission denied.[/red]"
            "\nRun the terminal with appropriate privileges."
        )
        return 1

    except OSError as exc:
        display.console.print(
            f"\n[red][!] Network capture error:[/red] {exc}"
        )
        return 1

    except ValueError as exc:
        display.console.print(
            f"\n[red][!] Configuration error:[/red] {exc}"
        )
        return 1

    except Exception as exc:
        display.console.print(
            f"\n[red][!] Unexpected error:[/red] {exc}"
        )
        return 1

    finally:
        display.show_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())

