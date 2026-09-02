from typing import Callable, Optional

from scapy.all import conf, sniff
from scapy.arch.windows import get_windows_if_list
from scapy.packet import Packet


SUPPORTED_BPF_FILTERS = {
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "ARP": "arp",
}


class PacketCapture:
    """Handle live network packet capture using Scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_count: int = 0,
        timeout: Optional[int] = None,
        protocol_filter: str = "ALL",
    ) -> None:
        self.interface = interface
        self.packet_count = packet_count
        self.timeout = timeout
        self.protocol_filter = protocol_filter.upper()

        if self.protocol_filter not in {
            "ALL",
            "TCP",
            "UDP",
            "ICMP",
            "ARP",
            "OTHER",
        }:
            raise ValueError(
                f"Unsupported protocol filter: {self.protocol_filter}"
            )

    def _resolve_interface(self):
        """Resolve the configured interface using Scapy."""

        if not self.interface:
            return conf.iface

        interface_name = self.interface.strip()

        # Refresh Scapy's interface registry.
        conf.ifaces.reload()

        # Direct Scapy lookup by name or description.
        try:
            return conf.ifaces.dev_from_name(interface_name)
        except ValueError:
            pass

        # Windows interface information can still identify the adapter
        # even when Scapy's registry was temporarily incomplete.
        try:
            windows_interfaces = get_windows_if_list()
        except Exception:
            windows_interfaces = []

        for windows_interface in windows_interfaces:
            name = windows_interface.get("name", "")
            description = windows_interface.get("description", "")
            guid = windows_interface.get("guid", "")

            if interface_name.lower() not in {
                name.lower(),
                description.lower(),
                guid.lower(),
            }:
                continue

            # Reload once more after Windows identified the adapter.
            conf.ifaces.reload()

            # Try the Windows interface name.
            try:
                return conf.ifaces.dev_from_name(name)
            except ValueError:
                pass

            # Try the Windows interface description.
            try:
                return conf.ifaces.dev_from_name(description)
            except ValueError:
                pass

            # Try the corresponding NPF device path.
            if guid:
                npf_guid = guid.strip("{}")
                npf_name = rf"\Device\NPF_{{{npf_guid}}}"

                try:
                    return conf.ifaces.dev_from_name(npf_name)
                except ValueError:
                    pass

                # Some Scapy versions expose the interface object
                # through the interface dictionary directly.
                for interface in conf.ifaces.values():
                    if str(interface) == npf_name:
                        return interface

        raise ValueError(
            f"Unknown network interface '{self.interface}'"
        )

    @staticmethod
    def _matches_protocol(packet: Packet, protocol: str) -> bool:
        """Check whether a packet matches the requested protocol."""

        if protocol == "ALL":
            return True

        if protocol == "TCP":
            return packet.haslayer("TCP")

        if protocol == "UDP":
            return packet.haslayer("UDP")

        if protocol == "ICMP":
            return packet.haslayer("ICMP")

        if protocol == "ARP":
            return packet.haslayer("ARP")

        if protocol == "OTHER":
            return not (
                packet.haslayer("TCP")
                or packet.haslayer("UDP")
                or packet.haslayer("ICMP")
                or packet.haslayer("ARP")
            )

        return False

    def start(self, callback: Callable[[Packet], None]) -> None:
        """Start capturing packets."""

        interface = self._resolve_interface()

        bpf_filter = SUPPORTED_BPF_FILTERS.get(self.protocol_filter)

        if bpf_filter:
            sniff(
                iface=interface,
                prn=callback,
                count=self.packet_count,
                timeout=self.timeout,
                filter=bpf_filter,
                store=False,
            )
            return

        if self.protocol_filter == "ALL":
            sniff(
                iface=interface,
                prn=callback,
                count=self.packet_count,
                timeout=self.timeout,
                store=False,
            )
            return

        matched_packets = 0

        def process_other(packet: Packet) -> None:
            nonlocal matched_packets

            if self._matches_protocol(packet, "OTHER"):
                matched_packets += 1
                callback(packet)

        def stop_when_complete(packet: Packet) -> bool:
            if self.packet_count <= 0:
                return False

            return matched_packets >= self.packet_count

        sniff(
            iface=interface,
            prn=process_other,
            count=0,
            timeout=self.timeout,
            stop_filter=stop_when_complete,
            store=False,
        )