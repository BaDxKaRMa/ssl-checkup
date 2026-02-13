![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Tests](https://img.shields.io/badge/tests-151%20passed-green)
![Coverage](https://img.shields.io/badge/coverage-95%25-green)
[![PyPI version](https://badge.fury.io/py/ssl-checkup.svg)](https://badge.fury.io/py/ssl-checkup)
[![Downloads](https://pepy.tech/badge/ssl-checkup)](https://pepy.tech/project/ssl-checkup)

# ssl-checkup

A robust, modular Python CLI tool for inspecting SSL/TLS certificates of remote servers. Features comprehensive testing, clean architecture, colorized output, and detailed debugging capabilities.

## Features

- **Certificate Analysis**: Check SSL certificate validity, issuer, subject, and SANs for any host
- **Colorized Output**: Beautiful, readable output with `--no-color` option for plain text
- **Debug Mode**: Comprehensive troubleshooting with `--debug` flag
- **Flexible Output**: Print PEM certificate, issuer, subject, or SANs only as needed
- **Error Handling**: Graceful handling of DNS/socket errors with helpful messages
- **Modular Architecture**: Clean, testable code structure with 95% test coverage
- **Easy Installation**: Available on PyPI - install with `pipx install ssl-checkup`

## Installation

### For Users (Recommended)

**Install with pipx for best isolation and to avoid dependency conflicts:**

```bash
pipx install ssl-checkup
```

If you don't have pipx, install it first:

```bash
# On macOS with Homebrew
brew install pipx

# On Ubuntu/Debian
sudo apt install pipx

# Or with pip
pip install --user pipx
pipx ensurepath
```

**Alternative: Install with pip (may cause dependency conflicts):**

```bash
pip install ssl-checkup
# Optional enhanced parsing and colors
pip install "ssl-checkup[full]"
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
pip install -e ".[dev,test,full]"
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

| Option               | Description                                                |
| -------------------- | ---------------------------------------------------------- |
| `--no-color`         | Disable color output for plain text                        |
| `--json`             | Output certificate data as JSON                            |
| `--json-pretty`      | Pretty-print JSON output (requires `--json`)               |
| `-p`, `--print-cert` | Print the PEM certificate to stdout                        |
| `--show-chain`       | Include certificate chain details in output                |
| `--debug`            | Enable debug output for troubleshooting                    |
| `-i`, `--issuer`     | Print only the certificate issuer                          |
| `-s`, `--subject`    | Print only the certificate subject                         |
| `-a`, `--san`        | Print only the Subject Alternative Names (SANs)            |
| `--warn-days N`      | Warning threshold in days before expiry (default: 30)      |
| `--critical-days N`  | Critical threshold in days before expiry (default: 7)      |
| `--timeout SEC`      | Connection timeout in seconds (default: 10)                |
| `--retries N`        | Retry attempts for transient network errors (default: 0)   |
| `--retry-delay SEC`  | Delay between retry attempts (default: 0.5)                |
| `--ip-version`       | `auto`, `4`, or `6` network family preference              |
| `--input FILE`       | Read targets from file (`-` reads from stdin)              |
| `--workers N`        | Worker threads for batch mode (`--input`)                  |
| `--summary`          | Show aggregate summary counts for batch runs               |
| `--fail-fast`        | Stop batch processing on first non-success result          |
| `--insecure`, `-k`   | Allow insecure connections (bypass certificate validation) |
| `--version`          | Show version and exit                                      |
| `-h`, `--help`       | Show help message                                          |

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

**JSON output and policy exit codes:**

```bash
ssl-checkup --json example.com
ssl-checkup --json --json-pretty example.com
ssl-checkup --json --show-chain example.com
ssl-checkup --retries 2 --retry-delay 1.0 example.com
ssl-checkup --warn-days 30 --critical-days 7 example.com
ssl-checkup --input targets.txt --json --summary
```

JSON schema (stable fields):

| Field            | Type                  | Notes |
| ---------------- | --------------------- | ----- |
| `target`         | string                | Original target input (e.g. `example.com:8443`) |
| `hostname`       | string                | Parsed hostname used for TLS SNI |
| `port`           | integer               | Parsed port |
| `resolved_ip`    | string \| null        | Remote IP if available |
| `tls_version`    | string \| null        | Negotiated TLS version |
| `cipher`         | array \| string \| null | Cipher details from Python SSL |
| `insecure`       | boolean               | Whether `--insecure` was enabled |
| `hostname_match` | boolean               | Hostname verification result against cert SAN/CN |
| `issuer`         | string \| null        | Issuer organization when available |
| `subject`        | string \| null        | Subject common name when available |
| `san`            | array[string]         | DNS SAN entries |
| `not_before`     | string \| null        | Certificate notBefore |
| `not_after`      | string \| null        | Certificate notAfter |
| `checked_at`     | string                | UTC timestamp in ISO-8601 format |
| `warning_days`   | integer               | Effective warning threshold |
| `critical_days`  | integer               | Effective critical threshold |
| `chain_source`   | string \| null        | Chain source: `verified`, `unverified`, or `leaf-only` |
| `chain`          | array[object]         | Present with `--show-chain`; includes `index`, `is_leaf`, `subject`, `issuer`, `not_before`, `not_after` |
| `status`         | string                | Present in policy mode: `valid`, `warning`, `critical`, `expired` |
| `days_left`      | integer               | Present in policy mode |

When `--summary` is used with `--json`, output becomes:
- `results`: array of per-target objects
- `summary`: aggregate counts (`total`, `valid`, `warning`, `critical`, `expired`, `errors`)

Exit codes in policy mode:
- `0` valid
- `1` warning
- `2` critical/expired
- `10+` operational errors (DNS/socket/SSL/internal)

**Batch checks:**

```bash
ssl-checkup --input targets.txt --workers 8
cat targets.txt | ssl-checkup --input - --json --workers 4
```

## Requirements

- **Python**: 3.11 or higher
- **Optional Dependencies** (install with `pip install "ssl-checkup[full]"`):
  - `termcolor>=3.1.0` (enhanced colorized output)
  - `cryptography>=45.0.5` (advanced certificate parsing)

_Note: The tool works without optional dependencies, with graceful fallbacks for missing features._

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

### Releasing (Maintainers)

This project uses automated PyPI publishing via GitHub Actions. To release a new version:

**Option 1: Using Makefile (Recommended)**
```bash
# Create and push a new release in one command
make release-push VERSION=1.1.0
```

**Option 2: Manual Process**
```bash
# 1. Update version in pyproject.toml
version = "1.1.1"

# 2. Commit and tag the release
git add pyproject.toml
git commit -m "Release v1.1.0"
git tag v1.1.0

# 3. Push to trigger automated PyPI upload
git push && git push --tags
```

**What happens automatically:**
- GitHub Actions builds the package with `uv`
- Runs quality checks with `twine check`
- Uploads to PyPI using stored API token
- New version is available within minutes

**Requirements for automated releases:**
- PyPI API token stored in GitHub Secrets as `PYPI_API_TOKEN`
- Version must follow semantic versioning (e.g., 1.0.0, 1.1.0, 2.0.0)

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

# Install with pipx (recommended for CLI tools)
pipx install ssl-checkup

# If pipx isn't available, install it first
pip install --user pipx
pipx ensurepath

# Alternative: Install with pip (may cause conflicts)
pip install ssl-checkup

# Or use uv for development
uv sync && uv run ssl-checkup example.com

# Force reinstall if needed
pipx reinstall ssl-checkup
```

## License

GPL-3.0 License - see LICENSE file for details.

---

**Project maintained by [BaDxKaRMa](https://github.com/BaDxKaRMa). Contributions welcome!**
