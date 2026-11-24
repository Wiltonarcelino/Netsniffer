import csv
import json
from datetime import datetime
from pathlib import Path
from data.models import PacketInfo
from utils.logger import setup_logger

logger = setup_logger()
REPORTS_DIR = Path("reports")


def _ensure_reports_dir() -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def export_to_csv(packets: list[PacketInfo], filename: str | None = None) -> Path:
    """Exporta a lista de pacotes para um arquivo CSV na pasta reports/."""
    _ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = REPORTS_DIR / (filename or f"captura_{stamp}.csv")

    with open(file_path, mode="w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow(["Hora", "Protocolo", "IP_Origem", "Porta_Origem", "IP_Destino", "Porta_Destino", "Tamanho_Bytes", "Detalhes"])
        for pkt in packets:
            writer.writerow([
                pkt.timestamp,
                pkt.protocol,
                pkt.src_ip,
                pkt.src_port or "",
                pkt.dst_ip,
                pkt.dst_port or "",
                pkt.length,
                pkt.info,
            ])

    logger.info(f"Relatório CSV exportado: {file_path} ({len(packets)} pacotes)")
    return file_path


def export_to_json(packets: list[PacketInfo], stats: dict, filename: str | None = None) -> Path:
    """Exporta estatísticas e pacotes para um arquivo JSON estruturado na pasta reports/."""
    _ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = REPORTS_DIR / (filename or f"captura_{stamp}.json")

    payload = {
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "resumo": stats,
        "total_exportado": len(packets),
        "pacotes": [
            {
                "timestamp": pkt.timestamp,
                "protocol": pkt.protocol,
                "src_ip": pkt.src_ip,
                "src_port": pkt.src_port,
                "dst_ip": pkt.dst_ip,
                "dst_port": pkt.dst_port,
                "length": pkt.length,
                "info": pkt.info,
            }
            for pkt in packets
        ],
    }

    with open(file_path, mode="w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    logger.info(f"Relatório JSON exportado: {file_path} ({len(packets)} pacotes)")
    return file_path


def export_to_txt(packets: list[PacketInfo], stats: dict, filename: str | None = None) -> Path:
    """Exporta um relatório legível em texto puro (TXT) na pasta reports/."""
    _ensure_reports_dir()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = REPORTS_DIR / (filename or f"captura_{stamp}.txt")

    lines = [
        "=" * 78,
        f"NETSNIFFER - RELATÓRIO DE TRÁFEGO DE REDE ({datetime.now().strftime('%d/%m/%Y %H:%M:%S')})",
        "=" * 78,
        f"Total de pacotes na sessão: {stats.get('total_packets', len(packets))}",
        f"Total de bytes trafegados:  {stats.get('total_bytes', 0)} B",
        f"Pacotes exportados:         {len(packets)}",
        "-" * 78,
        f"{'HORA':<13} {'PROTO':<6} {'ORIGEM':<22} {'DESTINO':<22} {'TAM':>6}  DETALHES",
        "-" * 78,
    ]

    for pkt in packets:
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
        lines.append(
            f"{pkt.timestamp:<13} {pkt.protocol:<6} {src:<22} {dst:<22} {pkt.length:>5}B  {pkt.info}"
        )

    with open(file_path, mode="w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    logger.info(f"Relatório TXT exportado: {file_path} ({len(packets)} pacotes)")
    return file_path