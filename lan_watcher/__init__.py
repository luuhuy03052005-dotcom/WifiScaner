"""LAN Watcher Pro package."""

__all__ = ["main"]

def main() -> None:
    from .cli import main as cli_main

    cli_main()
