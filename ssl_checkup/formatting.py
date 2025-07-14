from typing import Optional

"""Output formatting and display utilities."""

from typing import Any, Dict

# Handle optional termcolor dependency
try:
    from termcolor import colored
except ImportError:
    from typing import Iterable, Tuple, Union

    def colored(
        text: object,
        color: Union[str, Tuple[int, int, int], None] = None,
        on_color: Union[str, Tuple[int, int, int], None] = None,
        attrs: Union[Iterable[str], None] = None,
        *,
        no_color: Union[bool, None] = None,
        force_color: Union[bool, None] = None,
    ) -> str:
        return str(text)


class OutputFormatter:
    """Handles formatted output with optional color support."""

    def __init__(self, color_enabled: bool = True):
        self.color_enabled = color_enabled

    def cfield(self, text: str) -> str:
        """Format field names."""
        return colored(text, "white") if self.color_enabled else text

    def cissuer(self, text: str) -> str:
        """Format issuer text."""
        return colored(text, "magenta") if self.color_enabled else text

    def csubject(self, text: str, highlight: bool = False) -> str:
        """Format subject text."""
        if self.color_enabled:
            return colored(text, "cyan") if highlight else colored(text, "blue")
        return text

    def csan(self, text: str, highlight: bool = False) -> str:
        """Format SAN text."""
        if self.color_enabled:
            return colored(text, "cyan") if highlight else colored(text, "blue")
        return text

    def cplain(self, text: str) -> str:
        """Format plain text."""
        return colored(text, "white") if self.color_enabled else text

    def cquery(self, text: str) -> str:
        """Format query text."""
        return colored(text, "cyan") if self.color_enabled else text

    def format_status(self, days_left: int) -> str:
        """Format certificate status based on days remaining."""
        if self.color_enabled:
            if days_left < 0:
                return colored("EXPIRED", "red")
            elif days_left <= 30:
                return colored(f"WARNING ({days_left} days left)", "yellow")
            else:
                return colored(f"VALID ({days_left} days left)", "green")
        else:
            if days_left < 0:
                return "EXPIRED"
            elif days_left <= 30:
                return f"WARNING ({days_left} days left)"
            else:
                return f"VALID ({days_left} days left)"


class DebugFormatter:
    """Handles debug output formatting."""

    def __init__(self, color_enabled: bool = True):
        self.color_enabled = color_enabled

    def debug_header(self, text: str) -> str:
        """Format debug header."""
        if self.color_enabled:
            if text.startswith("\n"):
                return "\n[" + colored("DEBUG", "red") + "]" + text.split("]", 1)[-1]
            else:
                return "[" + colored("DEBUG", "red") + "]" + text.split("]", 1)[-1]
        return text

    def print_connection_details(
        self,
        hostname: str,
        port: int,
        cert_info: Dict[str, Any],
        start_time: Optional[float] = None,
    ):
        """Print debug connection information."""
        import time

        print(self.debug_header("[DEBUG] Connection details:"))
        print(f"  Hostname: {hostname}")
        print(f"  Port: {port}")
        print(f"  Resolved IP: {cert_info.get('resolved_ip', 'N/A')}")
        print(f"  TLS Version: {cert_info.get('tls_version', 'N/A')}")
        print(f"  Cipher: {cert_info.get('cipher', 'N/A')}")
        if start_time is not None:
            print(f"  Time to connect/fetch: {time.time() - start_time:.3f} seconds")

    def print_cert_details(self, cert_info: Dict[str, Any], insecure: bool = False):
        """Print debug certificate information."""
        import pprint

        print(self.debug_header("[DEBUG] Raw certificate dict:"))
        raw_cert = cert_info.get("cert")
        if not raw_cert and insecure:
            print("  (Empty when using --insecure - this is expected)")
        pprint.pprint(raw_cert)
        print(self.debug_header("[DEBUG] PEM certificate:"))
        print(cert_info.get("pem"))

    def print_query_analysis(self, hostname: str, cert: Dict[str, Any]):
        """Print debug query matching analysis."""
        from .parser import get_subject_cn, parse_san

        print("\n" + self.debug_header("[DEBUG] Query:") + f" {hostname}")

        subject_val = get_subject_cn(cert)
        print(self.debug_header("[DEBUG] Subject:") + f" {subject_val}")

        san = parse_san(cert)
        print(self.debug_header("[DEBUG] SANs:") + f" {san}")

        matches = [name for name in san if name.lower() == hostname.lower()]
        if subject_val and subject_val.lower() == hostname.lower():
            print(self.debug_header("[DEBUG] Query matches subject."))
        if matches:
            print(self.debug_header(f"[DEBUG] Query matches SAN(s): {matches}"))
        else:
            print(self.debug_header("[DEBUG] Query does not match any SAN."))
