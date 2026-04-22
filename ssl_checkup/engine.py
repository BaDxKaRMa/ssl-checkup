"""Runtime engine for SSL checks and output rendering."""

import ipaddress
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Type

from .exceptions import EXIT_OPERATIONAL_ERROR
from .parser import get_issuer_org, get_subject_cn, parse_pem_cert, parse_san

STATUS_VALID = "valid"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_EXPIRED = "expired"


def _arg(args: Any, name: str, default: Any) -> Any:
    """Read argparse values safely, including mocked test objects."""
    try:
        return vars(args).get(name, default)
    except TypeError:
        return getattr(args, name, default)


def print_single_field(cert: Dict[str, Any], field_type: str) -> None:
    """Print a single certificate field."""
    if field_type == "issuer":
        value = get_issuer_org(cert)
    elif field_type == "subject":
        value = get_subject_cn(cert)
    elif field_type == "san":
        san_list = parse_san(cert)
        for name in san_list:
            print(name)
        return
    else:
        raise ValueError(f"Unknown field type: {field_type}")

    print(value if value else "N/A")


def colorize_pretty_json(text: str, color_fn: Callable[[str, str], str]) -> str:
    """Apply ANSI colors to pretty JSON token types for terminal output."""
    result: list[str] = []
    i = 0
    length = len(text)

    while i < length:
        char = text[i]

        if char in " \t\r\n":
            result.append(char)
            i += 1
            continue

        if char == '"':
            start = i
            i += 1
            while i < length:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            token = text[start:i]
            j = i
            while j < length and text[j] in " \t\r\n":
                j += 1
            is_key = j < length and text[j] == ":"
            result.append(color_fn(token, "cyan" if is_key else "green"))
            continue

        if char == "-" or char.isdigit():
            start = i
            i += 1
            while i < length and text[i] in "0123456789.eE+-":
                i += 1
            result.append(color_fn(text[start:i], "yellow"))
            continue

        if text.startswith("true", i) or text.startswith("false", i):
            token = "true" if text.startswith("true", i) else "false"
            i += len(token)
            result.append(color_fn(token, "magenta"))
            continue

        if text.startswith("null", i):
            i += 4
            result.append(color_fn("null", "red"))
            continue

        result.append(text[i])
        i += 1

    return "".join(result)


def print_json(
    data: Any,
    pretty: bool,
    color_output: bool,
    color_fn: Callable[[str, str], str],
) -> None:
    """Print JSON payload."""
    if pretty:
        pretty_json = json.dumps(data, indent=2, sort_keys=True, default=str)
        stdout_is_tty = bool(getattr(sys.stdout, "isatty", lambda: False)())
        if color_output and stdout_is_tty:
            print(colorize_pretty_json(pretty_json, color_fn))
        else:
            print(pretty_json)
    else:
        print(json.dumps(data, separators=(",", ":"), default=str))


@dataclass(frozen=True)
class EngineDeps:
    """Runtime dependency bundle for testability."""

    get_certificate: Callable[..., Any]
    pretty_print_cert: Callable[..., None]
    print_single_field: Callable[[Dict[str, Any], str], None]
    debug_formatter_cls: Type[Any]
    colored: Callable[[str, str], str]
    handle_keyboard_interrupt: Callable[[], int]


class CheckEngine:
    """Executes SSL check targets and handles rendering/exit policy."""

    def __init__(self, args: Any, deps: EngineDeps):
        self.args = args
        self.deps = deps

    def run_targets(
        self, targets: list[tuple[str, int, str]], input_path: str | None
    ) -> int:
        """Run checks for all targets with one unified execution flow."""
        try:
            results = self._execute_targets(targets)
            summary = self._build_batch_summary(results)
            self._emit_results(results, summary, input_path)
            return self._batch_exit_code(results)
        except KeyboardInterrupt:
            return self.deps.handle_keyboard_interrupt()

    def _is_policy_mode(self) -> bool:
        return not (
            _arg(self.args, "print_cert", False)
            or _arg(self.args, "issuer", False)
            or _arg(self.args, "subject", False)
            or _arg(self.args, "san", False)
        )

    def _is_json_mode(self) -> bool:
        return bool(
            _arg(self.args, "json", False) or _arg(self.args, "json_pretty", False)
        )

    def _status_to_exit_code(self, status: str) -> int:
        if status in (STATUS_EXPIRED, STATUS_CRITICAL):
            return 2
        if status == STATUS_WARNING:
            return 1
        return 0

    def _result_exit_code(self, result: Dict[str, Any]) -> int:
        if result.get("error"):
            return EXIT_OPERATIONAL_ERROR
        if not self._is_policy_mode():
            return 0
        return self._status_to_exit_code(result.get("status", STATUS_VALID))

    def _batch_exit_code(self, results: list[Dict[str, Any]]) -> int:
        if any(result.get("error") for result in results):
            return EXIT_OPERATIONAL_ERROR
        if not self._is_policy_mode():
            return 0
        worst = 0
        for result in results:
            status = result.get("status", STATUS_VALID)
            worst = max(worst, self._status_to_exit_code(status))
        return worst

    def _calculate_status(self, cert: Dict[str, Any]) -> Dict[str, Any]:
        not_after = cert.get("notAfter")
        if not not_after:
            raise ValueError(
                "Could not determine certificate expiration date (notAfter)"
            )

        expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expire_date - datetime.now(timezone.utc)).days

        warn_days = int(_arg(self.args, "warn_days", 30))
        critical_days = int(_arg(self.args, "critical_days", 7))

        if days_left < 0:
            status = STATUS_EXPIRED
        elif days_left <= critical_days:
            status = STATUS_CRITICAL
        elif days_left <= warn_days:
            status = STATUS_WARNING
        else:
            status = STATUS_VALID

        return {"days_left": days_left, "status": status}

    def _resolve_display_cert(
        self, cert: Dict[str, Any], cert_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        if cert.get("notAfter"):
            return cert

        if _arg(self.args, "insecure", False):
            pem_data = cert_info.get("pem")
            if pem_data:
                parsed_cert = parse_pem_cert(pem_data)
                if parsed_cert:
                    return parsed_cert

        return cert

    def _hostname_matches(self, cert: Dict[str, Any], hostname: str) -> bool:
        hostname_lower = hostname.lower()

        def _dns_name_matches(pattern: str) -> bool:
            normalized = pattern.lower()
            if "*" not in normalized:
                return normalized == hostname_lower
            if normalized.startswith("*.") and normalized.count("*") == 1:
                if "." not in hostname_lower:
                    return False
                return hostname_lower.split(".", 1)[1] == normalized[2:]
            return False

        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            is_ip = False

        san_entries = cert.get("subjectAltName", [])
        dns_names = [entry[1] for entry in san_entries if entry[0] == "DNS"]
        ip_names = [
            entry[1] for entry in san_entries if entry[0] in ("IP Address", "IP")
        ]

        if is_ip:
            return hostname in ip_names if ip_names else False

        if dns_names:
            return any(_dns_name_matches(pattern) for pattern in dns_names)

        subject_name = get_subject_cn(cert)
        return _dns_name_matches(subject_name) if subject_name else False

    def _build_chain_summary(self, chain_pem: list[str]) -> list[Dict[str, Any]]:
        summary: list[Dict[str, Any]] = []
        for index, pem_data in enumerate(chain_pem):
            parsed = parse_pem_cert(pem_data)
            entry: Dict[str, Any] = {
                "index": index,
                "is_leaf": index == 0,
                "subject": None,
                "issuer": None,
                "not_before": None,
                "not_after": None,
            }
            if parsed:
                entry["subject"] = get_subject_cn(parsed)
                entry["issuer"] = get_issuer_org(parsed)
                entry["not_before"] = parsed.get("notBefore")
                entry["not_after"] = parsed.get("notAfter")
            summary.append(entry)
        return summary

    def _print_chain_summary(
        self, chain: list[Dict[str, Any]], source: str | None
    ) -> None:
        if not chain:
            print("  Chain: unavailable")
            return

        heading = "Certificate Chain"
        if source:
            heading += f" ({source})"
        print(f"  {heading}:")
        for entry in chain:
            role = "leaf" if entry.get("is_leaf") else "intermediate/root"
            subject = entry.get("subject") or "N/A"
            issuer = entry.get("issuer") or "N/A"
            not_after = entry.get("not_after") or "N/A"
            print(
                f"    - [{entry.get('index')}] {role} | "
                f"subject={subject} | issuer={issuer} | not_after={not_after}"
            )

    def _is_retryable_error(self, exc: Exception) -> bool:
        if isinstance(exc, socket.gaierror):
            return False
        if isinstance(exc, ssl.SSLError):
            return "CERTIFICATE_VERIFY_FAILED" not in str(exc)
        return isinstance(exc, (socket.timeout, TimeoutError, OSError, ConnectionError))

    def _get_certificate_with_retries(
        self, hostname: str, port: int, pem: bool = False, **cert_kwargs: Any
    ) -> Any:
        retries = int(_arg(self.args, "retries", 0))
        retry_delay = float(_arg(self.args, "retry_delay", 0.5))
        attempt = 0

        while True:
            try:
                if pem:
                    return self.deps.get_certificate(
                        hostname, port, pem=True, **cert_kwargs
                    )
                return self.deps.get_certificate(hostname, port, **cert_kwargs)
            except Exception as exc:
                if attempt >= retries or not self._is_retryable_error(exc):
                    raise
                attempt += 1
                if _arg(self.args, "debug", False):
                    print(
                        f"[DEBUG] Retry {attempt}/{retries} after error: {exc}",
                        file=sys.stderr,
                    )
                if retry_delay > 0:
                    time.sleep(retry_delay)

    def _build_json_result(
        self,
        hostname: str,
        port: int,
        raw_target: str,
        cert_info: Dict[str, Any],
        cert: Dict[str, Any],
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "target": raw_target,
            "hostname": hostname,
            "port": port,
            "resolved_ip": cert_info.get("resolved_ip"),
            "tls_version": cert_info.get("tls_version"),
            "cipher": cert_info.get("cipher"),
            "insecure": bool(_arg(self.args, "insecure", False)),
            "hostname_match": self._hostname_matches(cert, hostname),
            "issuer": get_issuer_org(cert),
            "subject": get_subject_cn(cert),
            "san": parse_san(cert),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "checked_at": datetime.now(timezone.utc).isoformat() + "Z",
            "warning_days": _arg(self.args, "warn_days", 30),
            "critical_days": _arg(self.args, "critical_days", 7),
        }

        if self._is_policy_mode():
            result.update(self._calculate_status(cert))

        if _arg(self.args, "show_chain", False):
            chain_pem = cert_info.get("chain_pem") or []
            result["chain_source"] = cert_info.get("chain_source")
            result["chain"] = self._build_chain_summary(chain_pem)

        return result

    def _run_target(self, hostname: str, port: int, raw_target: str) -> Dict[str, Any]:
        try:
            cert_kwargs: Dict[str, Any] = {
                "insecure": bool(_arg(self.args, "insecure", False)),
                "timeout": float(_arg(self.args, "timeout", 10.0)),
                "ip_version": str(_arg(self.args, "ip_version", "auto")),
            }
            if _arg(self.args, "show_chain", False):
                cert_kwargs["include_chain"] = True

            debug = bool(_arg(self.args, "debug", False))
            color_output = not bool(_arg(self.args, "no_color", False))
            debug_formatter = (
                self.deps.debug_formatter_cls(color_output) if debug else None
            )
            start_time = time.time() if debug else None

            if _arg(self.args, "print_cert", False):
                pem = self._get_certificate_with_retries(
                    hostname, port, pem=True, **cert_kwargs
                )
                return {
                    "target": raw_target,
                    "hostname": hostname,
                    "port": port,
                    "pem": pem,
                }

            cert_info = self._get_certificate_with_retries(
                hostname, port, **cert_kwargs
            )
            if not isinstance(cert_info, dict):
                raise ValueError("Could not parse certificate details.")

            if debug and debug_formatter:
                debug_formatter.print_connection_details(
                    hostname, port, cert_info, start_time
                )
                debug_formatter.print_cert_details(
                    cert_info, bool(_arg(self.args, "insecure", False))
                )

            cert = cert_info.get("cert")
            if not isinstance(cert, dict):
                raise ValueError("Could not parse certificate details.")

            display_cert = self._resolve_display_cert(cert, cert_info)
            result = self._build_json_result(
                hostname, port, raw_target, cert_info, display_cert
            )
            result["cert"] = display_cert
            result["pem"] = cert_info.get("pem")

            if debug and debug_formatter:
                debug_formatter.print_query_analysis(hostname, display_cert)

            return result
        except Exception as exc:
            error_kind = "general_error"
            if isinstance(exc, socket.gaierror):
                error_kind = "socket_error"
            elif isinstance(exc, ssl.SSLError):
                error_kind = "ssl_error"

            return {
                "target": raw_target,
                "hostname": hostname,
                "port": port,
                "error": {
                    "kind": error_kind,
                    "message": str(exc),
                },
            }

    def _execute_targets(
        self, targets: list[tuple[str, int, str]]
    ) -> list[Dict[str, Any]]:
        fail_fast = bool(_arg(self.args, "fail_fast", False))
        if fail_fast:
            results: list[Dict[str, Any]] = []
            for hostname, port, raw_target in targets:
                result = self._run_target(hostname, port, raw_target)
                results.append(result)
                if self._result_exit_code(result) != 0:
                    break
            return results

        workers = int(_arg(self.args, "workers", 4))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._run_target, hostname, port, raw_target)
                for hostname, port, raw_target in targets
            ]
            return [future.result() for future in futures]

    def _build_batch_summary(self, results: list[Dict[str, Any]]) -> Dict[str, int]:
        summary = {
            "total": len(results),
            "valid": 0,
            "warning": 0,
            "critical": 0,
            "expired": 0,
            "errors": 0,
        }

        for result in results:
            if result.get("error"):
                summary["errors"] += 1
                continue

            if self._is_policy_mode():
                status = result.get("status", STATUS_VALID)
                if status in summary:
                    summary[status] += 1
                else:
                    summary["valid"] += 1
            else:
                summary["valid"] += 1

        return summary

    def _print_batch_summary(self, summary: Dict[str, int]) -> None:
        print("Batch Summary:")
        print(
            "  "
            f"total={summary['total']} "
            f"valid={summary['valid']} "
            f"warning={summary['warning']} "
            f"critical={summary['critical']} "
            f"expired={summary['expired']} "
            f"errors={summary['errors']}"
        )

    def _print_target_human(self, result: Dict[str, Any], is_batch: bool) -> None:
        if result.get("error"):
            err = result["error"]
            print(
                f"Error for {result['target']}: "
                f"{err.get('kind')} - {err.get('message')}",
                file=sys.stderr,
            )
            return

        if is_batch:
            print(f"==> {result['target']}")

        cert = result.get("cert") or {}
        hostname = result["hostname"]
        port = result["port"]

        if _arg(self.args, "print_cert", False):
            print(result.get("pem") or "")
        elif _arg(self.args, "issuer", False):
            self.deps.print_single_field(cert, "issuer")
        elif _arg(self.args, "subject", False):
            self.deps.print_single_field(cert, "subject")
        elif _arg(self.args, "san", False):
            self.deps.print_single_field(cert, "san")
        else:
            self.deps.pretty_print_cert(
                cert,
                hostname,
                port,
                _arg(self.args, "warn_days", 30),
                not bool(_arg(self.args, "no_color", False)),
                result.get("pem"),
                bool(_arg(self.args, "insecure", False)),
            )

        if _arg(self.args, "show_chain", False):
            chain = result.get("chain") or []
            self._print_chain_summary(chain, result.get("chain_source"))

    def _emit_results(
        self,
        results: list[Dict[str, Any]],
        summary: Dict[str, int],
        input_path: str | None,
    ) -> None:
        if self._is_json_mode():
            payload: Any = results
            if len(results) == 1 and not input_path:
                payload = results[0]
            if _arg(self.args, "summary", False):
                if isinstance(payload, list):
                    payload = {"results": payload, "summary": summary}
                else:
                    payload = {"results": [payload], "summary": summary}
            print_json(
                payload,
                pretty=bool(_arg(self.args, "json_pretty", False)),
                color_output=not bool(_arg(self.args, "no_color", False)),
                color_fn=self.deps.colored,
            )
            return

        for index, result in enumerate(results):
            self._print_target_human(result, is_batch=len(results) > 1)
            if len(results) > 1 and index < len(results) - 1:
                print()

        if _arg(self.args, "summary", False):
            self._print_batch_summary(summary)
