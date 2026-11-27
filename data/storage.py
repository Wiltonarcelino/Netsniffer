import threading
import ipaddress
from collections import Counter, deque
from typing import Optional
from typing import Dict, List
from config import MAX_PACKET_BUFFER
from data.models import PacketInfo


class TrafficStorage:
    """Armazena pacotes recentes e estatísticas de tráfego de forma thread-safe."""

    def __init__(self, max_packets: int = MAX_PACKET_BUFFER) -> None:
        self._lock = threading.Lock()
        self._security_alerts: list[PacketInfo] = []
        self._packets: deque[PacketInfo] = deque(maxlen=max_packets)
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.ip_counts: Counter = Counter()

    def add_packet(self, packet: PacketInfo) -> None:
        """Registra um novo pacote no buffer circular e atualiza os contadores."""
        with self._lock:
            self._packets.append(packet)
            if "[ALERTA:" in packet.info:
                self._security_alerts.append(packet)
            self.total_packets += 1
            self.total_bytes += packet.length
            self.protocol_counts[packet.protocol] += 1
            self.ip_counts[packet.src_ip] += 1
            self.ip_counts[packet.dst_ip] += 1

    def get_recent_packets(self, limit: int = 20) -> List[PacketInfo]:
        """Retorna uma cópia segura dos ultimos N pacotes capturados."""
        with self._lock:
            return list(self._packets)[-limit:]

    def get_summary(self) -> Dict[str, object]:
        """Retorna um retrato consolidado das estatísticas atuais."""
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "protocols": dict(self.protocol_counts),
                "top_ips": self.ip_counts.most_common(5),
            }

    def clear(self) -> None:
        """Zera o buffer e todas as estatísticas para iniciar uma nova captura."""
        with self._lock:
            self._packets.clear()
            self._security_alerts.clear()
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.ip_counts.clear()

    def search_packets(
        self,
        ip: str | None = None,
        protocol: str | None = None,
        port: int | None = None,
        keyword: str | None = None,
        limit: int = 50,
    ) -> list[PacketInfo]:
        """Filtra todo o buffer armazenado antes de aplicar o limite de exibição."""
        ip_clean = ip.strip() if ip and ip.strip() else None
        proto_clean = protocol.strip().upper() if protocol and protocol.strip() else None
        kw_clean = keyword.strip().lower() if keyword and keyword.strip() else None

        with self._lock:
            if kw_clean and "alerta" in kw_clean:
                packets = list(self._security_alerts)
            else:
                packets = list(self._packets)

        results: list[PacketInfo] = []
        # Percorre do mais recente para o mais antigo em TODO o buffer
        for pkt in reversed(packets):
            if ip_clean and ip_clean not in pkt.src_ip and ip_clean not in pkt.dst_ip:
                continue
            if proto_clean and pkt.protocol.upper() != proto_clean:
                continue
            if port is not None and pkt.src_port != port and pkt.dst_port != port:
                continue
            if kw_clean and kw_clean not in pkt.info.lower():
                continue

            results.append(pkt)
            if len(results) >= limit:
                break

        return list(reversed(results))
    
    # DIZER O DOMINIO DO IP
    def get_public_ips(self, limit: int = 10) -> list[str]:
        """Retorna uma lista de IPs públicos únicos vistos nos pacotes armazenados."""
        with self._lock:
            packets = list(self._packets)

        public_ips: list[str] = []
        seen: set[str] = set()

        for pkt in reversed(packets):
            for candidate in (pkt.src_ip, pkt.dst_ip):
                if candidate in seen:
                    continue
                seen.add(candidate)
                try:
                    ip_obj = ipaddress.ip_address(candidate)
                    if not (
                        ip_obj.is_private
                        or ip_obj.is_loopback
                        or ip_obj.is_multicast
                        or ip_obj.is_reserved
                    ):
                        public_ips.append(candidate)
                        if len(public_ips) >= limit:
                            return public_ips
                except ValueError:
                    continue

        return public_ips