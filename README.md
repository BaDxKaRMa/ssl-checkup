# ssl-checkup

A robust, user-friendly Python CLI tool for inspecting SSL/TLS certificates of remote servers. Designed for easy installation, colorized output, and detailed debugging.

## Features

- Checks SSL certificate validity, issuer, subject, and SANs for any host.
- Colorized, readable output (with `--no-color` option).
- Debug mode for troubleshooting (`--debug`).
- Prints PEM certificate, issuer, subject, or SANs only, if requested.
- Handles DNS/socket errors gracefully.
- Ready for installation as a global CLI tool via `pipx` or `uv`.

## Installation

### For Users (recommended)

From the project directory, install globally with pipx:

```
pipx install .
```

After installation, you can run `ssl-checkup` from anywhere:

```
ssl-checkup example.com
```

If you want to run directly from the repo without installing:

```
python ssl_checkup.py example.com
```

### For Development

If you are developing or contributing, you may use [uv](https://github.com/astral-sh/uv) for faster dependency management:

```
uv init
uv sync
```

## Usage

```
ssl-checkup [OPTIONS] WEBSITE[:PORT]
```

- `WEBSITE` is the domain or IP to check (default port is 443, or specify with `:PORT`).

### Options

- `--no-color` Disable color output
- `-p`, `--print-cert` Print the PEM certificate to stdout
- `--debug` Enable debug output for troubleshooting
- `-i`, `--issuer` Print only the issuer
- `-s`, `--subject` Print only the subject
- `-a`, `--san` Print only the Subject Alternative Names (SANs)
- `--version` Show version and exit

### Examples

Check a website's certificate:

```
ssl-checkup example.com
```

Check a custom port:

```
ssl-checkup example.com:8443
```

Print only the issuer:

```
ssl-checkup -i example.com
```

Print the PEM certificate:

```
ssl-checkup -p example.com
```

Enable debug output:

```
ssl-checkup --debug example.com
```

## Troubleshooting

If you see an error about `termcolor` not being installed, run:

```
pip install termcolor
```

---

_Project maintained by Ralph Hittell. Contributions welcome!_
