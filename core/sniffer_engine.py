import socket
import threading
from typing import Optional
from scapy.config import conf
from scapy.layers.inet import IP
from scapy.sendrecv import AsyncSniffer
from scapy.packet import Packet
from core.packet_parser import parse_packet
from data.storage import TrafficStorage
from utils.logger import setup_logger
from utils.validators import get_network_interfaces

logger = setup_logger()


class SnifferEngine:
    """Gerencia a captura de pacotes em segundo plano usando AsyncSniffer do Scapy."""

    def __init__(self, storage: TrafficStorage, interface: Optional[str] = None) -> None:
        self.storage = storage
        self.interface = interface
        self.bpf_filter: str = ""
        self._sniffer: Optional[AsyncSniffer] = None
        self.is_running: bool = False

    def _process_packet(self, raw_packet: Packet) -> None:
        """Callback chamado pelo Scapy a cada pacote capturado na placa de rede."""
        try:
            parsed = parse_packet(raw_packet)
            if parsed is not None:
                self.storage.add_packet(parsed)
        except Exception as exc:
            logger.error(f"Erro ao processar pacote: {exc}")
    def set_filter(self, bpf_filter: str) -> None:
        """Define o filtro BPF (ex: 'tcp port 443', 'udp', 'icmp')."""
        self.bpf_filter = bpf_filter.strip()

    def _get_active_ipv4(self) -> str:
        """Descobre o IPv4 da placa de rede ativa (UP) para abrir o Raw Socket no Windows."""
        for iface in get_network_interfaces():
            if iface["status"] == "UP" and iface["ip"] not in ("Sem IPv4", "127.0.0.1"):
                return iface["ip"]
        return "127.0.0.1"

    def _raw_socket_loop(self, bind_ip: str) -> None:
        """Captura pacotes IPv4 em tempo real no Windows usando apenas socket nativo."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((bind_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        sock.settimeout(1.0)

        try:
            while self.is_running:
                try:
                    raw_data, _ = sock.recvfrom(65535)
                    scapy_pkt = IP(raw_data)
                    self._process_packet(scapy_pkt)
                except socket.timeout:
                    continue
        finally:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()

    def start(self) -> tuple[bool, str]:
        """Inicia a captura em segundo plano (Npcap ou Raw Socket nativo do Windows)."""
        if self.is_running:
            return False, "A captura já está em andamento."

        # Se não houver Npcap/libpcap no Windows, usa Raw Socket nativo (Camada 3 IPv4)
        if not conf.use_pcap:
            try:
                bind_ip = self._get_active_ipv4()
                self.is_running = True
                self._raw_thread = threading.Thread(
                    target=self._raw_socket_loop, args=(bind_ip,), daemon=True
                )
                self._raw_thread.start()
                logger.info(f"Captura nativa (Raw Socket) iniciada no IP {bind_ip}")
                return True, f"Captura nativa iniciada no IP {bind_ip} (sem driver externo)."
            except Exception as exc:
                self.is_running = False
                logger.error(f"Falha no Raw Socket nativo: {exc}")
                return False, f"Falha ao iniciar captura nativa: {exc}"

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.bpf_filter or None,
                store=False,
            )
            self._sniffer.start()
            self.is_running = True
            logger.info("Captura iniciada via libpcap/Npcap.")
            return True, "Captura iniciada com sucesso."
        except Exception as exc:
            self.is_running = False
            logger.error(f"Falha ao iniciar captura: {exc}")
            return False, f"Falha ao iniciar captura: {exc}"

    def stop(self) -> tuple[bool, str]:
        """Para a captura em segundo plano com segurança."""
        if not self.is_running:
            return False, "Nenhuma captura está ativa no momento."

        self.is_running = False

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.warning(f"Aviso ao encerrar sniffer: {exc}")
            finally:
                self._sniffer = None

        logger.info("Captura encerrada.")
        return True, "Captura encerrada."