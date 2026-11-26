from datetime import UTC, datetime

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import CookedLinux, Dot1Q, Ether, Loopback
from scapy.packet import Packet

from security_detection_engine.network.models import NetworkPacketRecord


def _outer_ip(packet: Packet) -> IP | None:
    while isinstance(packet, (Ether, Dot1Q, CookedLinux, Loopback)):
        packet = packet.payload
    if not isinstance(packet, IP) or packet.frag or packet.flags.MF:
        return None
    transport = {6: TCP, 17: UDP, 1: ICMP}.get(packet.proto)
    return packet if transport and isinstance(packet.payload, transport) else None


def is_supported_packet(packet: Packet) -> bool:
    """Проверяет, содержит ли пакет поддерживаемые IPv4/TCP/UDP/ICMP данные."""
    return _outer_ip(packet) is not None


def parse_packet(packet: Packet) -> NetworkPacketRecord | None:
    """Извлекает сетевые метаданные из пакета Scapy.

    Возвращает None для пакетов без поддерживаемого содержимого
    и для пакетов с некорректными данными.
    """
    ip = _outer_ip(packet)
    if ip is None:
        return None

    transport = ip.payload

    try:
        timestamp = datetime.fromtimestamp(float(packet.time), tz=UTC)

        if isinstance(transport, TCP):
            protocol = "tcp"
            source_port = transport.sport
            destination_port = transport.dport
            tcp_flags = str(transport.flags)
        elif isinstance(transport, UDP):
            protocol = "udp"
            source_port = transport.sport
            destination_port = transport.dport
            tcp_flags = None
        else:
            protocol = "icmp"
            source_port = None
            destination_port = None
            tcp_flags = None

        return NetworkPacketRecord(
            timestamp=timestamp,
            source_ip=ip.src,
            destination_ip=ip.dst,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_size=len(packet),
            tcp_flags=tcp_flags,
        )
    except (ValueError, TypeError, OverflowError, OSError):
        # Некорректный timestamp, порты или адреса — пакет пропускается
        return None
