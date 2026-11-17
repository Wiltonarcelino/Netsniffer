import ctypes
from ctypes import util
import ipaddress
import os
import platform
from typing import Dict, List
import psutil
from scapy.all import conf


def is_admin() -> bool:
    """Verifica se o script está a ser executado com privilégios de Administrador/Root."""
    if platform.system() == "Windows":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def is_valid_ip(ip_str: str) -> bool:
    """Valida se uma string é um endereço IPv4 ou IPv6 válido."""
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_public_ip(ip_str: str) -> bool:
    """Retorna True se o IP for público (roteável na internet), False se for local/privado."""
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_global
    except ValueError:
        return False


def get_network_interfaces() -> List[Dict[str, str]]:
    """Lista todas as interfaces de rede do sistema com seu IPv4 e status (UP/DOWN)."""
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface_name, iface_addrs in addrs.items():
        ipv4 = "Sem IPv4"
        for addr in iface_addrs:
            if addr.family.name == "AF_INET":
                ipv4 = addr.address
                break

        is_up = stats[iface_name].isup if iface_name in stats else False

        interfaces.append(
            {
                "name": iface_name,
                "ip": ipv4,
                "status": "UP" if is_up else "DOWN",
            }
        )

    return interfaces


def get_default_interface() -> str:
    """Retorna a interface de rede padrão escolhida automaticamente pelo Scapy."""
    return str(conf.iface)