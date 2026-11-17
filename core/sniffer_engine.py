from typing import Optional
from scapy.sendrecv import AsyncSniffer
from scapy.packet import Packet
from core.packet_parser import parse_packet
from data.storage import TrafficStorage
from utils.logger import setup_logger

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

    def start(self) -> tuple[bool, str]:
        """Inicia a captura em segundo plano. Retorna (sucesso, mensagem)."""
        if self.is_running:
            return False, "A captura já está em andamento."

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                prn=self._process_packet,
                filter=self.bpf_filter or None,
                store=False,
            )
            self._sniffer.start()
            self.is_running = True
            logger.info(
                f"Captura iniciada | Interface={self.interface or 'Padrão'} | Filtro='{self.bpf_filter}'"
            )
            return True, "Captura iniciada com sucesso."
        except Exception as exc:
            self.is_running = False
            logger.error(f"Falha ao iniciar captura: {exc}")
            return False, f"Falha ao iniciar captura: {exc}"

    def stop(self) -> tuple[bool, str]:
        """Para a captura em segundo plano com segurança."""
        if not self.is_running or self._sniffer is None:
            return False, "Nenhuma captura está ativa no momento."

        try:
            self._sniffer.stop()
        except Exception as exc:
            logger.warning(f"Aviso ao encerrar sniffer: {exc}")
        finally:
            self.is_running = False
            self._sniffer = None
            logger.info("Captura encerrada.")

        return True, "Captura encerrada."