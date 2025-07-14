"""Tests for formatting module."""

from unittest.mock import patch

from ssl_checkup.formatting import DebugFormatter, OutputFormatter


class TestOutputFormatter:
    """Test output formatting functionality."""

    def test_output_formatter_color_enabled(self):
        """Test output formatter with color enabled."""
        formatter = OutputFormatter(color_enabled=True)

        assert formatter.color_enabled is True

    def test_output_formatter_color_disabled(self):
        """Test output formatter with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        assert formatter.color_enabled is False

    def test_cfield_with_color(self):
        """Test field formatting with color enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "white_text"

            result = formatter.cfield("test")

            mock_colored.assert_called_once_with("test", "white")
            assert result == "white_text"

    def test_cfield_without_color(self):
        """Test field formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.cfield("test")

        assert result == "test"

    def test_cissuer_with_color(self):
        """Test issuer formatting with color enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "magenta_text"

            result = formatter.cissuer("issuer")

            mock_colored.assert_called_once_with("issuer", "magenta")
            assert result == "magenta_text"

    def test_cissuer_without_color(self):
        """Test issuer formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.cissuer("issuer")

        assert result == "issuer"

    def test_csubject_with_color_highlight(self):
        """Test subject formatting with color and highlight enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "cyan_text"

            result = formatter.csubject("subject", highlight=True)

            mock_colored.assert_called_once_with("subject", "cyan")
            assert result == "cyan_text"

    def test_csubject_with_color_no_highlight(self):
        """Test subject formatting with color and no highlight."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "blue_text"

            result = formatter.csubject("subject", highlight=False)

            mock_colored.assert_called_once_with("subject", "blue")
            assert result == "blue_text"

    def test_csubject_without_color(self):
        """Test subject formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.csubject("subject", highlight=True)

        assert result == "subject"

    def test_csan_with_color_highlight(self):
        """Test SAN formatting with color and highlight enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "cyan_text"

            result = formatter.csan("san", highlight=True)

            mock_colored.assert_called_once_with("san", "cyan")
            assert result == "cyan_text"

    def test_csan_with_color_no_highlight(self):
        """Test SAN formatting with color and no highlight."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "blue_text"

            result = formatter.csan("san", highlight=False)

            mock_colored.assert_called_once_with("san", "blue")
            assert result == "blue_text"

    def test_csan_without_color(self):
        """Test SAN formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.csan("san", highlight=True)

        assert result == "san"

    def test_cplain_with_color(self):
        """Test plain text formatting with color enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "white_text"

            result = formatter.cplain("plain")

            mock_colored.assert_called_once_with("plain", "white")
            assert result == "white_text"

    def test_cplain_without_color(self):
        """Test plain text formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.cplain("plain")

        assert result == "plain"

    def test_cquery_with_color(self):
        """Test query formatting with color enabled."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "cyan_text"

            result = formatter.cquery("query")

            mock_colored.assert_called_once_with("query", "cyan")
            assert result == "cyan_text"

    def test_cquery_without_color(self):
        """Test query formatting with color disabled."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.cquery("query")

        assert result == "query"

    def test_format_status_expired_with_color(self):
        """Test status formatting for expired certificate with color."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "red_text"

            result = formatter.format_status(-5)

            mock_colored.assert_called_once_with("EXPIRED", "red")
            assert result == "red_text"

    def test_format_status_expired_without_color(self):
        """Test status formatting for expired certificate without color."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.format_status(-5)

        assert result == "EXPIRED"

    def test_format_status_warning_with_color(self):
        """Test status formatting for warning certificate with color."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "yellow_text"

            result = formatter.format_status(15)

            mock_colored.assert_called_once_with("WARNING (15 days left)", "yellow")
            assert result == "yellow_text"

    def test_format_status_warning_without_color(self):
        """Test status formatting for warning certificate without color."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.format_status(15)

        assert result == "WARNING (15 days left)"

    def test_format_status_valid_with_color(self):
        """Test status formatting for valid certificate with color."""
        formatter = OutputFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "green_text"

            result = formatter.format_status(90)

            mock_colored.assert_called_once_with("VALID (90 days left)", "green")
            assert result == "green_text"

    def test_format_status_valid_without_color(self):
        """Test status formatting for valid certificate without color."""
        formatter = OutputFormatter(color_enabled=False)

        result = formatter.format_status(90)

        assert result == "VALID (90 days left)"

    def test_format_status_boundary_conditions(self):
        """Test status formatting at boundary conditions."""
        formatter = OutputFormatter(color_enabled=False)

        # Exactly 30 days - should be warning
        result = formatter.format_status(30)
        assert "WARNING (30 days left)" in result

        # 31 days - should be valid
        result = formatter.format_status(31)
        assert "VALID (31 days left)" in result

        # -1 days - should be expired
        result = formatter.format_status(-1)
        assert "EXPIRED" in result


class TestDebugFormatter:
    """Test debug formatting functionality."""

    def test_debug_formatter_color_enabled(self):
        """Test debug formatter with color enabled."""
        formatter = DebugFormatter(color_enabled=True)

        assert formatter.color_enabled is True

    def test_debug_formatter_color_disabled(self):
        """Test debug formatter with color disabled."""
        formatter = DebugFormatter(color_enabled=False)

        assert formatter.color_enabled is False

    def test_debug_header_with_color(self):
        """Test debug header formatting with color enabled."""
        formatter = DebugFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "red_text"

            result = formatter.debug_header("[DEBUG] Test message")

            mock_colored.assert_called_once_with("DEBUG", "red")
            assert "red_text" in result

    def test_debug_header_without_color(self):
        """Test debug header formatting with color disabled."""
        formatter = DebugFormatter(color_enabled=False)

        result = formatter.debug_header("[DEBUG] Test message")

        assert result == "[DEBUG] Test message"

    def test_debug_header_with_newline(self):
        """Test debug header formatting with newline at start."""
        formatter = DebugFormatter(color_enabled=True)

        with patch("ssl_checkup.formatting.colored") as mock_colored:
            mock_colored.return_value = "red_text"

            result = formatter.debug_header("\n[DEBUG] Test message")

            mock_colored.assert_called_once_with("DEBUG", "red")
            assert result.startswith("\n[")
            assert "red_text" in result

    @patch("builtins.print")
    @patch("time.time")
    def test_print_connection_details(self, mock_time, mock_print):
        """Test printing connection details."""
        formatter = DebugFormatter(color_enabled=False)
        mock_time.return_value = 1.0

        cert_info = {
            "resolved_ip": "192.168.1.1",
            "tls_version": "TLSv1.3",
            "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        }

        formatter.print_connection_details("example.com", 443, cert_info, 0.5)

        # Check that print was called multiple times with connection details
        assert mock_print.call_count >= 6

        # Check some of the printed content
        printed_calls = [call[0][0] for call in mock_print.call_args_list]
        assert any("Connection details:" in call for call in printed_calls)
        assert any("Hostname: example.com" in call for call in printed_calls)
        assert any("Port: 443" in call for call in printed_calls)
        assert any("Resolved IP: 192.168.1.1" in call for call in printed_calls)
        assert any("TLS Version: TLSv1.3" in call for call in printed_calls)

    @patch("builtins.print")
    @patch("pprint.pprint")
    def test_print_cert_details(self, mock_pprint, mock_print):
        """Test printing certificate details."""
        formatter = DebugFormatter(color_enabled=False)

        cert_info = {
            "cert": {"subject": [["commonName", "example.com"]]},
            "pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        }

        formatter.print_cert_details(cert_info, False)

        # Check that print was called for debug headers
        assert mock_print.call_count >= 2

        # Check that pprint was called with the cert
        mock_pprint.assert_called_once_with(cert_info["cert"])

    @patch("builtins.print")
    @patch("pprint.pprint")
    def test_print_cert_details_insecure(self, mock_pprint, mock_print):
        """Test printing certificate details in insecure mode."""
        formatter = DebugFormatter(color_enabled=False)

        cert_info = {
            "cert": None,
            "pem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
        }

        formatter.print_cert_details(cert_info, True)

        # Check that print was called
        assert mock_print.call_count >= 3

        # Check that one of the prints mentions insecure mode
        printed_calls = [call[0][0] for call in mock_print.call_args_list]
        assert any("Empty when using --insecure" in call for call in printed_calls)

    @patch("builtins.print")
    @patch("ssl_checkup.parser.get_subject_cn")
    @patch("ssl_checkup.parser.parse_san")
    def test_print_query_analysis(
        self, mock_parse_san, mock_get_subject_cn, mock_print
    ):
        """Test printing query analysis."""
        formatter = DebugFormatter(color_enabled=False)

        mock_get_subject_cn.return_value = "example.com"
        mock_parse_san.return_value = ["example.com", "www.example.com"]

        cert = {"subject": [["commonName", "example.com"]]}

        formatter.print_query_analysis("example.com", cert)

        # Check that print was called multiple times
        assert mock_print.call_count >= 5

        # Check some of the printed content
        printed_calls = [call[0][0] for call in mock_print.call_args_list]
        assert any("Query: example.com" in call for call in printed_calls)
        assert any("Subject: example.com" in call for call in printed_calls)
        assert any("Query matches subject" in call for call in printed_calls)

    @patch("builtins.print")
    @patch("ssl_checkup.parser.get_subject_cn")
    @patch("ssl_checkup.parser.parse_san")
    def test_print_query_analysis_no_match(
        self, mock_parse_san, mock_get_subject_cn, mock_print
    ):
        """Test printing query analysis with no matches."""
        formatter = DebugFormatter(color_enabled=False)

        mock_get_subject_cn.return_value = "different.com"
        mock_parse_san.return_value = ["other.com", "another.com"]

        cert = {"subject": [["commonName", "different.com"]]}

        formatter.print_query_analysis("example.com", cert)

        # Check that print was called
        assert mock_print.call_count >= 4

        # Check that no match message is printed
        printed_calls = [call[0][0] for call in mock_print.call_args_list]
        assert any("Query does not match any SAN" in call for call in printed_calls)
