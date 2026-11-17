from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class PacketInfo:
    """Representa um pacote de rede capturado e já interpretado."""
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    length: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""

    @classmethod
    def now_timestamp(cls) -> str:
        """Gera o horário atual formatado com milissegundos."""
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]