from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from config import APP_NAME, APP_VERSION
from core.sniffer_engine import SnifferEngine
from data.storage import TrafficStorage
from utils.validators import get_default_interface, is_admin

console = Console()


class TerminalUI:
    """Gerencia o menu interativo e a exibição de tabelas/estatísticas no terminal."""

    def __init__(self, storage: TrafficStorage, engine: SnifferEngine) -> None:
        self.storage = storage
        self.engine = engine

    def render_header(self) -> None:
        """Exibe o cabeçalho com status atual da captura, filtro e privilégios."""
        status = (
            "[bold green]● CAPTURANDO[/bold green]"
            if self.engine.is_running
            else "[bold red]■ PARADO[/bold red]"
        )
        iface = self.engine.interface or get_default_interface()
        filtro = self.engine.bpf_filter or "Nenhum (Todo o tráfego)"
        admin_badge = "[green]Admin[/green]" if is_admin() else "[yellow]Sem Admin[/yellow]"

        console.print(
            Panel(
                f"[bold cyan]{APP_NAME} v{APP_VERSION}[/bold cyan]  |  Status: {status}  |  Privilégios: {admin_badge}\n"
                f"Interface: [white]{iface}[/white]  |  Filtro BPF: [magenta]{filtro}[/magenta]  |  "
                f"Pacotes: [bold]{self.storage.total_packets}[/bold]",
                border_style="cyan",
            )
        )

    def show_recent_packets(self, limit: int = 15) -> None:
        """Exibe uma tabela formatada com os últimos pacotes capturados."""
        packets = self.storage.get_recent_packets(limit=limit)
        if not packets:
            console.print("[yellow]Nenhum pacote capturado até o momento.[/yellow]")
            return

        table = Table(title=f"Últimos {len(packets)} Pacotes Capturados", header_style="bold cyan")
        table.add_column("Hora", style="dim", width=12)
        table.add_column("Proto", style="bold magenta", width=7)
        table.add_column("Origem", style="green")
        table.add_column("Destino", style="cyan")
        table.add_column("Tam.", justify="right", width=7)
        table.add_column("Detalhes", style="white")

        for pkt in packets:
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
            table.add_row(pkt.timestamp, pkt.protocol, src, dst, f"{pkt.length}B", pkt.info)

        console.print(table)
    def show_statistics(self) -> None:
        """Exibe estatísticas consolidadas de protocolos e IPs mais ativos."""
        summary = self.storage.get_summary()
        if summary["total_packets"] == 0:
            console.print("[yellow]Ainda não há dados estatísticos para exibir.[/yellow]")
            return

        console.print(
            f"\n[bold]Total de Pacotes:[/bold] {summary['total_packets']}  |  "
            f"[bold]Volume Total:[/bold] {summary['total_bytes']} bytes\n"
        )

        proto_table = Table(title="Distribuição por Protocolo", header_style="bold magenta")
        proto_table.add_column("Protocolo", style="cyan")
        proto_table.add_column("Pacotes", justify="right", style="green")

        for proto, count in summary["protocols"].items():
            proto_table.add_row(proto, str(count))

        ip_table = Table(title="Top 5 IPs Mais Ativos", header_style="bold magenta")
        ip_table.add_column("Endereço IP", style="cyan")
        ip_table.add_column("Pacotes", justify="right", style="green")

        for ip, count in summary["top_ips"]:
            ip_table.add_row(ip, str(count))

        console.print(proto_table)
        console.print(ip_table)

    def run(self) -> None:
        """Loop principal do menu interativo no terminal."""
        while True:
            console.print()
            self.render_header()
            console.print(
                "[bold cyan][1][/bold cyan] Iniciar Captura    "
                "[bold cyan][2][/bold cyan] Parar Captura\n"
                "[bold cyan][3][/bold cyan] Ver Últimos Pacotes "
                "[bold cyan][4][/bold cyan] Estatísticas\n"
                "[bold cyan][5][/bold cyan] Definir Filtro BPF  "
                "[bold cyan][6][/bold cyan] Limpar Dados\n"
                "[bold red][0][/bold red] Sair"
            )

            choice = Prompt.ask("\nEscolha uma opção", choices=["0", "1", "2", "3", "4", "5", "6"], default="3")

            if choice == "1":
                ok, msg = self.engine.start()
                color = "green" if ok else "red"
                console.print(f"[{color}]{msg}[/{color}]")

            elif choice == "2":
                ok, msg = self.engine.stop()
                color = "yellow" if ok else "red"
                console.print(f"[{color}]{msg}[/{color}]")

            elif choice == "3":
                self.show_recent_packets()

            elif choice == "4":
                self.show_statistics()

            elif choice == "5":
                if self.engine.is_running:
                    console.print("[yellow]Pare a captura antes de alterar o filtro BPF.[/yellow]")
                else:
                    new_filter = Prompt.ask("Filtro BPF (ex: tcp port 443, udp, icmp ou vazio para limpar)", default="")
                    self.engine.set_filter(new_filter)
                    console.print(f"[green]Filtro atualizado para:[/green] '{self.engine.bpf_filter or 'Nenhum'}'")

            elif choice == "6":
                self.storage.clear()
                console.print("[green]Buffer e estatísticas zerados com sucesso.[/green]")

            elif choice == "0":
                if self.engine.is_running:
                    self.engine.stop()
                console.print("[bold cyan]Encerrando NetSniffer. Até logo![/bold cyan]")
                break    