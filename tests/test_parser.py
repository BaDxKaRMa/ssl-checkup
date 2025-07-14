"""Tests for parser module."""

from unittest.mock import Mock, patch

from ssl_checkup.parser import (
    extract_cert_field,
    get_issuer_org,
    get_subject_cn,
    parse_pem_cert,
    parse_san,
)


class TestParseSan:
    """Test Subject Alternative Names parsing."""

    def test_parse_san_multiple_dns(self, sample_cert):
        """Test parsing multiple DNS entries from SAN."""
        san = parse_san(sample_cert)

        assert len(san) == 3
        assert "example.com" in san
        assert "www.example.com" in san
        assert "api.example.com" in san

    def test_parse_san_single_dns(self):
        """Test parsing single DNS entry from SAN."""
        cert = {"subjectAltName": [("DNS", "example.com")]}

        san = parse_san(cert)

        assert len(san) == 1
        assert san[0] == "example.com"

    def test_parse_san_no_dns(self):
        """Test parsing SAN with no DNS entries."""
        cert = {
            "subjectAltName": [
                ("IP Address", "192.168.1.1"),
                ("email", "test@example.com"),
            ]
        }

        san = parse_san(cert)

        assert len(san) == 0

    def test_parse_san_missing_field(self):
        """Test parsing SAN when field is missing."""
        cert = {}

        san = parse_san(cert)

        assert len(san) == 0

    def test_parse_san_empty_field(self):
        """Test parsing SAN when field is empty."""
        cert = {"subjectAltName": []}

        san = parse_san(cert)

        assert len(san) == 0

    def test_parse_san_mixed_entries(self):
        """Test parsing SAN with mixed entry types."""
        cert = {
            "subjectAltName": [
                ("DNS", "example.com"),
                ("IP Address", "192.168.1.1"),
                ("DNS", "www.example.com"),
                ("email", "test@example.com"),
            ]
        }

        san = parse_san(cert)

        assert len(san) == 2
        assert "example.com" in san
        assert "www.example.com" in san


class TestExtractCertField:
    """Test certificate field extraction."""

    def test_extract_subject_common_name(self, sample_cert):
        """Test extracting common name from subject."""
        result = extract_cert_field(sample_cert, "subject", ["commonName"])

        assert result == "example.com"

    def test_extract_issuer_organization(self, sample_cert):
        """Test extracting organization from issuer."""
        result = extract_cert_field(sample_cert, "issuer", ["organizationName"])

        assert result == "Let's Encrypt"

    def test_extract_field_multiple_names(self, sample_cert):
        """Test extracting field with multiple possible names."""
        result = extract_cert_field(sample_cert, "subject", ["CN", "commonName"])

        assert result == "example.com"

    def test_extract_field_not_found(self, sample_cert):
        """Test extracting field that doesn't exist."""
        result = extract_cert_field(sample_cert, "subject", ["nonexistent"])

        assert result is None

    def test_extract_field_empty_cert(self):
        """Test extracting field from empty certificate."""
        cert = {}

        result = extract_cert_field(cert, "subject", ["commonName"])

        assert result is None

    def test_extract_field_malformed_data(self):
        """Test extracting field from malformed certificate data."""
        cert = {"subject": ["not a tuple"]}

        # This should not raise an exception, but return None gracefully
        result = extract_cert_field(cert, "subject", ["commonName"])

        assert result is None


class TestGetSubjectCn:
    """Test subject common name extraction."""

    def test_get_subject_cn_success(self, sample_cert):
        """Test successful subject CN extraction."""
        result = get_subject_cn(sample_cert)

        assert result == "example.com"

    def test_get_subject_cn_missing(self):
        """Test subject CN extraction when missing."""
        cert = {
            "subject": [[("countryName", "US")], [("organizationName", "Example Corp")]]
        }

        result = get_subject_cn(cert)

        assert result is None

    def test_get_subject_cn_empty_cert(self):
        """Test subject CN extraction from empty certificate."""
        cert = {}

        result = get_subject_cn(cert)

        assert result is None


class TestGetIssuerOrg:
    """Test issuer organization extraction."""

    def test_get_issuer_org_success(self, sample_cert):
        """Test successful issuer organization extraction."""
        result = get_issuer_org(sample_cert)

        assert result == "Let's Encrypt"

    def test_get_issuer_org_missing(self):
        """Test issuer organization extraction when missing."""
        cert = {"issuer": [[("countryName", "US")], [("commonName", "Root CA")]]}

        result = get_issuer_org(cert)

        assert result is None

    def test_get_issuer_org_empty_cert(self):
        """Test issuer organization extraction from empty certificate."""
        cert = {}

        result = get_issuer_org(cert)

        assert result is None


class TestParsePemCert:
    """Test PEM certificate parsing."""

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_success(self, sample_pem_cert):
        """Test successful PEM certificate parsing."""
        # Mock the cryptography library
        with patch("ssl_checkup.parser.x509") as mock_x509:
            mock_cert = Mock()
            mock_cert.not_valid_after_utc.strftime.return_value = (
                "Dec 15 23:59:59 2024 GMT"
            )
            mock_cert.not_valid_before_utc.strftime.return_value = (
                "Sep 15 00:00:00 2024 GMT"
            )

            # Mock subject and issuer
            mock_subject_attr = Mock()
            mock_subject_attr.oid._name = "commonName"
            mock_subject_attr.value = "example.com"
            mock_cert.subject = [mock_subject_attr]

            mock_issuer_attr = Mock()
            mock_issuer_attr.oid._name = "organizationName"
            mock_issuer_attr.value = "Example CA"
            mock_cert.issuer = [mock_issuer_attr]

            # Mock SAN extension
            mock_san_ext = Mock()
            mock_san_ext.value.get_values_for_type.return_value = [
                "example.com",
                "www.example.com",
            ]
            mock_cert.extensions.get_extension_for_oid.return_value = mock_san_ext

            mock_x509.load_pem_x509_certificate.return_value = mock_cert

            result = parse_pem_cert(sample_pem_cert)

            assert result is not None
            assert result["notAfter"] == "Dec 15 23:59:59 2024 GMT"
            assert result["notBefore"] == "Sep 15 00:00:00 2024 GMT"
            assert result["subject"] == [[("commonName", "example.com")]]
            assert result["issuer"] == [[("organizationName", "Example CA")]]
            assert result["subjectAltName"] == [
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
            ]

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", False)
    def test_parse_pem_cert_no_cryptography(self, sample_pem_cert):
        """Test PEM certificate parsing when cryptography is not available."""
        result = parse_pem_cert(sample_pem_cert)

        assert result is None

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_none_input(self):
        """Test PEM certificate parsing with None input."""
        result = parse_pem_cert(None)

        assert result is None

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_empty_input(self):
        """Test PEM certificate parsing with empty input."""
        result = parse_pem_cert("")

        assert result is None

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_invalid_pem(self):
        """Test PEM certificate parsing with invalid PEM data."""
        with patch("ssl_checkup.parser.x509") as mock_x509:
            mock_x509.load_pem_x509_certificate.side_effect = Exception("Invalid PEM")

            result = parse_pem_cert("invalid pem data")

            assert result is None

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_no_san(self, sample_pem_cert):
        """Test PEM certificate parsing with no SAN extension."""
        with patch("ssl_checkup.parser.x509") as mock_x509:
            mock_cert = Mock()
            mock_cert.not_valid_after_utc.strftime.return_value = (
                "Dec 15 23:59:59 2024 GMT"
            )
            mock_cert.not_valid_before_utc.strftime.return_value = (
                "Sep 15 00:00:00 2024 GMT"
            )

            mock_subject_attr = Mock()
            mock_subject_attr.oid._name = "commonName"
            mock_subject_attr.value = "example.com"
            mock_cert.subject = [mock_subject_attr]

            mock_issuer_attr = Mock()
            mock_issuer_attr.oid._name = "organizationName"
            mock_issuer_attr.value = "Example CA"
            mock_cert.issuer = [mock_issuer_attr]

            # Mock missing SAN extension
            mock_cert.extensions.get_extension_for_oid.side_effect = (
                mock_x509.ExtensionNotFound("No SAN")
            )

            mock_x509.load_pem_x509_certificate.return_value = mock_cert

            result = parse_pem_cert(sample_pem_cert)

            assert result is not None
            assert result["subjectAltName"] == []

    @patch("ssl_checkup.parser.CRYPTOGRAPHY_AVAILABLE", True)
    def test_parse_pem_cert_san_fallback(self, sample_pem_cert):
        """Test PEM certificate parsing with SAN fallback for different
        cryptography versions."""
        with patch("ssl_checkup.parser.x509") as mock_x509:
            mock_cert = Mock()
            mock_cert.not_valid_after_utc.strftime.return_value = (
                "Dec 15 23:59:59 2024 GMT"
            )
            mock_cert.not_valid_before_utc.strftime.return_value = (
                "Sep 15 00:00:00 2024 GMT"
            )

            mock_subject_attr = Mock()
            mock_subject_attr.oid._name = "commonName"
            mock_subject_attr.value = "example.com"
            mock_cert.subject = [mock_subject_attr]

            mock_issuer_attr = Mock()
            mock_issuer_attr.oid._name = "organizationName"
            mock_issuer_attr.value = "Example CA"
            mock_cert.issuer = [mock_issuer_attr]

            # Mock SAN extension that fails with AttributeError
            mock_san_ext = Mock()
            mock_san_ext.value.get_values_for_type.side_effect = AttributeError(
                "Method not available"
            )
            mock_cert.extensions.get_extension_for_oid.return_value = mock_san_ext

            mock_x509.load_pem_x509_certificate.return_value = mock_cert

            result = parse_pem_cert(sample_pem_cert)

            assert result is not None
            assert result["subjectAltName"] == []
