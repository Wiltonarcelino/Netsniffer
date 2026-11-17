from core.sniffer_engine import SnifferEngine
from data.storage import TrafficStorage
from ui.terminal_ui import TerminalUI
from utils.logger import setup_logger

logger = setup_logger()


def main() -> None:
    logger.info("Inicializando NetSniffer...")
    storage = TrafficStorage()
    engine = SnifferEngine(storage=storage)
    ui = TerminalUI(storage=storage, engine=engine)

    try:
        ui.run()
    except KeyboardInterrupt:
        if engine.is_running:
            engine.stop()
        print("\nExecução interrompida pelo usuário.")


if __name__ == "__main__":
    main()