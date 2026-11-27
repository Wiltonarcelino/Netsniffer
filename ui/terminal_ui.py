import time
import msvcrt
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from config import APP_NAME, APP_VERSION
from core.ip_inspector import inspect_ip
from core.sniffer_engine import SnifferEngine
from data.storage import TrafficStorage
from utils.validators import get_default_interface, is_admin
from core.exporter import export_to_csv, export_to_json, export_to_txt

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
    # NOVO TESTEE
    def _build_live_view(
        self, ip: str = "", protocol: str = "", keyword: str = "", limit: int = 20
    ) -> Table:
        """Monta a tabela atualizada para o painel em tempo real com filtros opcionais."""
        if ip or protocol or keyword:
            packets = self.storage.search_packets(
                ip=ip, protocol=protocol, keyword=keyword, limit=limit
            )
            filtro_label = f" | Filtro: IP='{ip or '*'}' Proto='{protocol or '*'}' Detalhe='{keyword or '*'}'"
        else:
            packets = self.storage.get_recent_packets(limit=limit)
            filtro_label = ""

        table = Table(
            title=(
                f"Monitoramento em Tempo Real{filtro_label} | Total: {self.storage.total_packets} "
                f"— [Pressione Q para voltar ao menu]"
            ),
            header_style="bold cyan",
        )
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

        return table

    def watch_live(self) -> None:
        """Exibe os pacotes subindo ao vivo até o usuário pressionar Q."""
        ip_filter = Prompt.ask("Filtrar por IP específico? (Enter para todos)", default="")
        proto_filter = Prompt.ask("Filtrar por protocolo (TCP, UDP, DNS, ICMP ou Enter para todos)", default="")
        detail_filter = Prompt.ask("Filtrar nos detalhes (ex: HTTPS, HTTP, Query ou Enter para todos)", default="")

        if not self.engine.is_running:
            self.engine.start()

        with Live(
            self._build_live_view(ip=ip_filter, protocol=proto_filter, keyword=detail_filter),
            refresh_per_second=4,
            console=console,
        ) as live:
            while True:
                if msvcrt.kbhit():
                    key = msvcrt.getch().decode("utf-8", errors="ignore").lower()
                    if key == "q":
                        break
                time.sleep(0.2)
                live.update(
                    self._build_live_view(ip=ip_filter, protocol=proto_filter, keyword=detail_filter)
                )
        while msvcrt.kbhit():
            msvcrt.getch()  # Limpa o buffer de teclas
        time.sleep(0.1)
        console.print("\n[yellow]Visualização ao vivo encerrada (captura continua em segundo plano).[/yellow]")

    #TESTE NOVO2
    def search_history(self) -> None:
        """Busca pacotes no histórico armazenado por IP, protocolo, porta ou detalhe."""
        if self.storage.total_packets == 0:
            console.print("[yellow]Nenhum pacote no histórico para pesquisar.[/yellow]")
            return

        ip = Prompt.ask("IP para rastrear (origem ou destino, Enter para ignorar)", default="")
        protocol = Prompt.ask("Protocolo (TCP, UDP, DNS, ICMP ou Enter para ignorar)", default="")
        port_raw = Prompt.ask("Porta (ex: 443, 53, 1521 ou Enter para ignorar)", default="")
        keyword = Prompt.ask("Detalhe (ex: HTTPS, HTTP, google ou Enter para ignorar)", default="")

        port = int(port_raw) if port_raw.isdigit() else None
        results = self.storage.search_packets(
            ip=ip, protocol=protocol, port=port, keyword=keyword, limit=40
        )

        if not results:
            console.print("[yellow]Nenhum pacote encontrado com esses critérios.[/yellow]")
            return

        table = Table(
            title=f"Resultados da Busca ({len(results)} pacotes exibidos)",
            header_style="bold green",
        )
        table.add_column("Hora", style="dim", width=12)
        table.add_column("Proto", style="bold magenta", width=7)
        table.add_column("Origem", style="green")
        table.add_column("Destino", style="cyan")
        table.add_column("Tam.", justify="right", width=7)
        table.add_column("Detalhes", style="white")

        for pkt in results:
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
            table.add_row(pkt.timestamp, pkt.protocol, src, dst, f"{pkt.length}B", pkt.info)

        console.print(table)
    #RASTREAR IP
    def inspect_remote_ip(self) -> None:
        """Exibe IPs públicos capturados e consulta geolocalização, provedor e ASN."""
        recent_public = self.storage.get_public_ips(limit=10)
        if recent_public:
            console.print(
                f"[dim]IPs públicos vistos recentemente:[/dim] [cyan]{', '.join(recent_public)}[/cyan]"
            )

        target_ip = Prompt.ask("Digite o IP que deseja inspecionar (ou Enter para cancelar)", default="").strip()
        if not target_ip:
            return

        with console.status(f"[cyan]Consultando dados de {target_ip}...[/cyan]"):
            info = inspect_ip(target_ip)

        if not info.get("ok"):
            console.print(f"[bold red]Erro:[/bold red] {info.get('error')}")
            return

        table = Table(title=f"Relatório OSINT / Rede — {info['ip']}", header_style="bold cyan")
        table.add_column("Atributo", style="bold white", width=18)
        table.add_column("Valor", style="green")

        table.add_row("Endereço IP", info["ip"])
        table.add_row("Classificação", info["type"])
        table.add_row("País / Região", info["country"])
        table.add_row("Cidade", info["city"])
        table.add_row("Provedor (ISP)", info["isp"])
        table.add_row("Organização", info["org"])
        table.add_row("Sistema Autônomo", info["as"])

        console.print(table)
    #importar arquivos .txt, .cvs
    def export_reports(self) -> None:
        """Exporta os pacotes armazenados em CSV, JSON, TXT ou todos os formatos."""
        if self.storage.total_packets == 0:
            console.print("[yellow]Nenhum pacote armazenado para exportar.[/yellow]")
            return

        fmt = Prompt.ask(
            "Escolha o formato de exportação",
            choices=["csv", "json", "txt", "todos"],
            default="todos",
        )

        # Pega até 5000 pacotes do histórico atual
        packets = self.storage.get_recent_packets(limit=5000)
        stats = {
            "total_packets": self.storage.total_packets,
            "total_bytes": self.storage.total_bytes,
            "protocols": dict(self.storage.protocol_counts),
        }

        created: list[str] = []
        if fmt in ("csv", "todos"):
            created.append(str(export_to_csv(packets)))
        if fmt in ("json", "todos"):
            created.append(str(export_to_json(packets, stats)))
        if fmt in ("txt", "todos"):
            created.append(str(export_to_txt(packets, stats)))

        console.print("[bold green]Relatório(s) gerado(s) com sucesso:[/bold green]")
        for path in created:
            console.print(f"  [cyan]-> {path}[/cyan]")

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
                "[bold green][7][/bold green] Ver Pacotes em Tempo Real\n"
                "[bold yellow][8][/bold yellow] Buscar / Filtrar no Histórico\n"
                "[bold magenta][9][/bold magenta] Inspecionar IP (Geo & ASN)\n"
                "[bold blue][10][/bold blue] Exportar Relatórios (CSV/JSON/TXT)\n"
                "[bold red][0][/bold red] Sair"
            )
            console.print("\n[bold]Escolha uma opção [0/1/2/3/4/5/6/7/8/9] (7):[/bold] ", end="")
            try:
                choice = input().strip() or "7"
            except (EOFError, KeyboardInterrupt):
                choice = "7"

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

            elif choice == "7":
                self.watch_live()

            elif choice == "8":
                self.search_history()

            elif choice == "9":
                self.inspect_remote_ip()

            elif choice == "10":
                self.export_reports()
                