"""SSL Certificate Checker - A robust SSL/TLS certificate inspection tool."""

__version__ = "1.2.0"


def main() -> None:
    """Run the CLI entry point lazily."""
    from .main import main as _main

    _main()


__all__ = ["main", "__version__"]
