import re
from config import MASK_CHAR, MASK_SENSITIVE_DATA

# padrões comuns de credenciais enviadas sem criptografia (HTTP POST/GET, FTP, Basic Auth)
_CLEARTEXT_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|senha|pass)\s*[=:]\s*([^\s&;\"']+)"),
    re.compile(r"(?i)(username|user|usuario|login|email)\s*[=:]\s*([^\s&;\"']+)"),
    re.compile(r"(?i)Authorization:\s*(Basic|Bearer)\s+([A-Za-z0-9+/=._-]+)"),
    re.compile(r"(?im)^PASS\s+([^\r\n]+)"),
]


def _format_secret(value: str) -> str:
    """Aplica ou remove o mascaramento de acordo com a flag em config.py."""
    if not MASK_SENSITIVE_DATA:
        return value
    return value[:2] + MASK_CHAR * max(4, len(value) - 2)


def detect_cleartext_credentials(playload_bytes: bytes) -> str | None:
    """
    Inspeciona bytes de playload TCP em busca de credenciais em texto claro.
    Retorna uma descrição mascarada (ou completa, se configurado) ou None se estiver limpo.
    """
    if not playload_bytes:
        return None

    # Ignora o tráfego binário/TLS (ClienteHello começa com 0x16 0x03)
    if len(playload_bytes) >= 2 and playload_bytes[0] in (0x14, 0x15, 0x16, 0x17) and playload_bytes[1] == 0x03:
        return None

    try:
        text = playload_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None

    # Descarta playloads sem caracteres legíveis suficientes
    if len(text.strip()) < 4:
        return None

    findings: list[str] = []
    for pattern in _CLEARTEXT_PATTERNS:
        match = pattern.search(text)
        if match:
            if match.lastindex and match.lastindex >= 2:
                field = match.group(1)
                value = match.group(2)
                findings.append(f"{field}={_format_secret(value)}")
            elif match.lastindex == 1:
                value = match.group(1).strip()
                findings.append(f"FTP_PASS={_format_secret(value)}")

    if findings:
        http_target = ""
        req_match = re.search(r"(?m)^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP/", text)
        host_match = re.search(r"(?im)^Host:\s*([^\r\n]+)", text)
        if req_match:
            method, path = req_match.group(1), req_match.group(2)
            host = host_match.group(1).strip() if host_match else ""
            http_target = f" ({method} {path} @ {host})" if host else f" ({method} {path})"
        elif host_match:
            http_target = f" (@ {host_match.group(1).strip()})"

        unique_findings = ", ".join(dict.fromkeys(findings))
        return f"[ALERTA: Credencial em Texto Claro{http_target} -> {unique_findings}]"

    return None