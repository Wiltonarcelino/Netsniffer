from typing import Optional
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR
from data.models import PacketInfo

COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}

def parse_packet(packet: Packet) -> Optional[PacketInfo]:
    """Extrai metadados de um pacote bruto do Scapy e retorna um PacketInfo."""
    # 1. Verifica se o pacote possui camada IPv4 ou IPv6; caso contrário, ignora
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return None

    length = len(packet)
    timestamp = PacketInfo.now_timestamp()
    protocol = "OTHER"
    src_port = None
    dst_port = None
    info = ""

    # 2. Identifica protocolos de transporte e aplicação
    if packet.haslayer(DNS):
        protocol = "DNS"
        if packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        if packet.haslayer(DNSQR) and packet[DNSQR].qname:
            domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            info = f"Query: {domain}"
        else:
            info = "DNS Response"

    elif packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)
        service = COMMON_PORTS.get(dst_port) or COMMON_PORTS.get(src_port) or ""
        prefix = f"{service} | " if service else ""
        info = f"{prefix}Flags: [{flags}]"
        
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        info = f"Len: {len(packet[UDP].payload)} bytes"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp_type = packet[ICMP].type
        info = "Echo Request (Ping)" if icmp_type == 8 else f"Type: {icmp_type}"

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=length,
        src_port=src_port,
        dst_port=dst_port,
        info=info,
    )