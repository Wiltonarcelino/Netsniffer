from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

APP_NAME = "NetSniffer"
APP_VERSION = "0.1.0"

MAX_PACKET_BUFFER = 5000
DEFAULT_INTERFACE = None

DEFAULT_SOCKET_TIMEOUT = 1.5
API_TIMEOUT = 5.0