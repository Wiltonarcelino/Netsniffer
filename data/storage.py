from collections import Counter, deque
import threading
from typing import Dict, List
from config import MAX_PACKET_BUFFER
from data.models import PacketInfo


class TrafficStorage:
    """Armazena pacotes recentes e estatísticas de tráfego de forma thread-safe."""

    def __init__(self, max_packets: int = MAX_PACKET_BUFFER) -> None:
        self._lock = threading.Lock()
        self._packets: deque[PacketInfo] = deque(maxlen=max_packets)
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counts: Counter = Counter()
        self.ip_counts: Counter = Counter()

    def add_packet(self, packet: PacketInfo) -> None:
        """Registra um novo pacote no buffer circular e atualiza os contadores."""
        with self._lock:
            self._packets.append(packet)
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
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.ip_counts.clear()