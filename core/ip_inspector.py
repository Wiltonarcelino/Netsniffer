import ipaddress
import requests
from utils.logger import setup_logger

logger = setup_logger()


def inspect_ip(ip_str: str) -> dict:
    """Consulta informações de geolocalização, provedor e ASN de um endereço IPv4."""
    ip_str = ip_str.strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return {"ok": False, "error": f"'{ip_str}' não é um endereço IP válido."}

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
        tipo = "Multicast" if ip_obj.is_multicast else "Privado / Rede Local"
        return {
            "ok": True,
            "ip": ip_str,
            "type": tipo,
            "country": "Rede Interna (LAN)",
            "city": "Local",
            "isp": "Infraestrutura Interna",
            "org": "Não roteável na Internet pública",
            "as": "N/A",
        }

    url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,regionName,city,isp,org,as,query"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            return {"ok": False, "error": data.get("message", "Falha ao consultar IP.")}

        logger.info(f"Consulta OSINT/IP realizada com sucesso para {ip_str}")
        return {
            "ok": True,
            "ip": data.get("query", ip_str),
            "type": "IP Público",
            "country": f"{data.get('country', 'N/A')} ({data.get('regionName', 'N/A')})",
            "city": data.get("city", "N/A"),
            "isp": data.get("isp", "N/A"),
            "org": data.get("org", "N/A"),
            "as": data.get("as", "N/A"),
        }
    except requests.RequestException as exc:
        logger.error(f"Erro de conexão ao consultar IP {ip_str}: {exc}")
        return {"ok": False, "error": f"Erro de conexão ao consultar API: {exc}"}