"""Main application CLI wiring and entry point."""

import contextlib
import json
import sys
import time  # noqa: F401
from typing import Any

from .cli import create_parser, handle_version_check, parse_website_arg, validate_args
from .connection import get_certificate
from .display import pretty_print_cert
from .engine import CheckEngine, EngineDeps, colorize_pretty_json, print_single_field
from .exceptions import handle_keyboard_interrupt
from .formatting import DebugFormatter, colored


def _arg(args: Any, name: str, default: Any) -> Any:
    """Read argparse values safely, including mocked test objects."""
    try:
        return vars(args).get(name, default)
    except TypeError:
        return getattr(args, name, default)


def _iter_input_targets(input_path: str) -> list[str]:
    """Read raw targets from input source."""
    if input_path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(input_path, encoding="utf-8") as handle:
            lines = handle.readlines()

    targets: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def _collect_targets(args: Any) -> tuple[list[tuple[str, int, str]], str | None]:
    """Collect and parse all targets from CLI args and optional input."""
    raw_targets: list[str] = []
    website = _arg(args, "website", None)
    if website:
        raw_targets.append(website)

    input_path = _arg(args, "input", None)
    if input_path:
        raw_targets.extend(_iter_input_targets(input_path))

    targets: list[tuple[str, int, str]] = []
    for raw_target in raw_targets:
        hostname, port = parse_website_arg(raw_target)
        targets.append((hostname, port, raw_target))

    return targets, input_path


def _colorize_pretty_json(text: str) -> str:
    """Apply syntax highlighting to pretty JSON output."""
    return colorize_pretty_json(text, colored)


def _print_json(data: Any, pretty: bool, color_output: bool) -> None:
    """Print JSON payload with optional pretty formatting and colors."""
    if pretty:
        pretty_json = json.dumps(data, indent=2, sort_keys=True, default=str)
        stdout_is_tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        if color_output and stdout_is_tty:
            print(_colorize_pretty_json(pretty_json))
        else:
            print(pretty_json)
    else:
        print(json.dumps(data, separators=(",", ":"), default=str))


def _build_deps() -> EngineDeps:
    return EngineDeps(
        get_certificate=get_certificate,
        pretty_print_cert=pretty_print_cert,
        print_single_field=print_single_field,
        debug_formatter_cls=DebugFormatter,
        colored=colored,
        handle_keyboard_interrupt=handle_keyboard_interrupt,
    )


def main() -> None:
    """Main application entry point."""
    parser = create_parser()
    args = parser.parse_args()

    handle_version_check(args)
    validate_args(args, parser)

    try:
        targets, input_path = _collect_targets(args)
    except ValueError as exc:
        parser.error(f"Invalid website argument: {exc}")
    except OSError as exc:
        parser.error(f"Could not read input targets: {exc}")

    if not targets:
        parser.error("No valid targets were provided")

    engine = CheckEngine(args=args, deps=_build_deps())

    output_path = _arg(args, "output", None)
    if output_path and output_path != "-":
        try:
            with open(output_path, "w", encoding="utf-8") as output_file:
                with contextlib.redirect_stdout(output_file):
                    exit_code = engine.run_targets(targets, input_path=input_path)
        except OSError as exc:
            parser.error(f"Could not open output file '{output_path}': {exc}")
    else:
        exit_code = engine.run_targets(targets, input_path=input_path)

    if exit_code != 0:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
