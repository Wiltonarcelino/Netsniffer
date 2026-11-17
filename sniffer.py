from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from config import APP_NAME, APP_VERSION
from utils.logger import setup_logger
from utils.validators import (
    get_default_interface,
    get_network_interfaces,
    is_admin,
)

console = Console()
logger = setup_logger()


def show_startup_banner() -> None:
    """Exibe o painel inicial com status de privilégios e interfaces de rede."""
    logger.info("Iniciando diagnóstico de ambiente do NetSniffer.")

    admin_ok = is_admin()
    default_iface = get_default_interface()
    interfaces = get_network_interfaces()

    priv_text = (
        "[bold green]OK (Administrador)[/bold green]"
        if admin_ok
        else "[bold yellow]LIMITADO (Sem Admin — captura local desativada)[/bold yellow]"
    )

    console.print(
        Panel.fit(
            f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan] — Network Traffic Analyzer\n"
            f"Privilégios: {priv_text}\n"
            f"Interface Padrão: [white]{default_iface}[/white]",
            border_style="cyan",
        )
    )

    table = Table(title="Interfaces de Rede Disponíveis", header_style="bold magenta")
    table.add_column("Interface", style="cyan")
    table.add_column("Endereço IPv4", style="green")
    table.add_column("Status", justify="center")

    for iface in interfaces:
        status = "[green]UP[/green]" if iface["status"] == "UP" else "[dim]DOWN[/dim]"
        table.add_row(iface["name"], iface["ip"], status)

    console.print(table)


if __name__ == "__main__":
    show_startup_banner()