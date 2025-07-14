
![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/github/license/BaDxKaRMa/ssl-checkup)
![Tests](https://img.shields.io/badge/tests-151%20passed-green)
![Coverage](https://img.shields.io/badge/coverage-95%25-green)

# ssl-checkup

A robust, modular Python CLI tool for inspecting SSL/TLS certificates of remote servers. Features comprehensive testing, clean architecture, colorized output, and detailed debugging capabilities.

## Features

- **Certificate Analysis**: Check SSL certificate validity, issuer, subject, and SANs for any host
- **Colorized Output**: Beautiful, readable output with `--no-color` option for plain text
- **Debug Mode**: Comprehensive troubleshooting with `--debug` flag
- **Flexible Output**: Print PEM certificate, issuer, subject, or SANs only as needed
- **Error Handling**: Graceful handling of DNS/socket errors with helpful messages
- **Modular Architecture**: Clean, testable code structure with 95% test coverage
- **Easy Installation**: Ready for global installation via `pipx`, `pip`, or `uv`

## Installation

### For Users (Recommended)

Install globally with pipx for best isolation:
```bash
pipx install ssl-checkup
```

Or install with pip:
```bash
pip install ssl-checkup
```

After installation, run from anywhere:
```bash
ssl-checkup example.com
```

### For Development

Clone and set up development environment:
```bash
git clone https://github.com/BaDxKaRMa/ssl-checkup.git
cd ssl-checkup

# Using uv (recommended)
uv sync
uv run ssl-checkup example.com

# Or using pip
pip install -e ".[dev,test]"
python -m ssl_checkup.main example.com
```

## Usage

```bash
ssl-checkup [OPTIONS] WEBSITE[:PORT]
```

**Arguments:**
- `WEBSITE` - Domain or IP address to check (default port: 443)
- `PORT` - Optional custom port (e.g., `example.com:8443`)

### Options

| Option | Description |
|--------|-------------|
| `--no-color` | Disable color output for plain text |
| `-p`, `--print-cert` | Print the PEM certificate to stdout |
| `--debug` | Enable debug output for troubleshooting |
| `-i`, `--issuer` | Print only the certificate issuer |
| `-s`, `--subject` | Print only the certificate subject |
| `-a`, `--san` | Print only the Subject Alternative Names (SANs) |
| `--insecure`, `-k` | Allow insecure connections (bypass certificate validation) |
| `--version` | Show version and exit |
| `-h`, `--help` | Show help message |

### Examples

**Basic certificate check:**
```bash
ssl-checkup example.com
```

**Check custom port:**
```bash
ssl-checkup example.com:8443
```

**Print specific certificate fields:**
```bash
ssl-checkup -i example.com          # Issuer only
ssl-checkup -s example.com          # Subject only  
ssl-checkup -a example.com          # SANs only
```

**Debug and troubleshooting:**
```bash
ssl-checkup --debug example.com     # Detailed debug output
ssl-checkup --insecure expired.badssl.com  # Skip validation
```

**Export certificate:**
```bash
ssl-checkup -p example.com > cert.pem       # Save PEM certificate
ssl-checkup --no-color example.com > info.txt  # Plain text output
```
## Requirements

- **Python**: 3.11 or higher
- **Optional Dependencies**: 
  - `termcolor>=3.1.0` (enhanced colorized output)
  - `cryptography>=45.0.5` (advanced certificate parsing)

*Note: The tool works without optional dependencies, with graceful fallbacks for missing features.*

## Development

### Quick Start

```bash
# Clone and set up development environment
git clone https://github.com/BaDxKaRMa/ssl-checkup.git
cd ssl-checkup
uv sync

# Run tests
make test

# Run with coverage
make test-coverage

# Run all quality checks
make check-all
```

### Contributing

1. **Fork and clone** the repository
2. **Set up development environment**: `uv sync`
3. **Run tests** to ensure everything works: `make test`
4. **Make your changes** with appropriate tests
5. **Run quality checks**: `make check-all`
6. **Submit a pull request**

## Troubleshooting

### Common Issues

**Missing dependencies:**
```bash
# For development - sync all dependencies
uv sync

# Or install individual packages if needed
uv pip install termcolor cryptography
```

**Connection issues:**
```bash
# Use debug mode for detailed troubleshooting
ssl-checkup --debug example.com

# Test insecure connections for self-signed certificates
ssl-checkup --insecure your-internal-server.com
```

**Installation issues:**
```bash
# Ensure Python 3.11+
python --version

# Use pipx for isolated installation (recommended)
pipx install ssl-checkup

# Or use uv for development
uv sync && uv run ssl-checkup example.com

# Force reinstall if needed
pipx reinstall ssl-checkup
```

## License

GPL-3.0 License - see LICENSE file for details.

---

**Project maintained by [BaDxKaRMa](https://github.com/BaDxKaRMa). Contributions welcome!**
