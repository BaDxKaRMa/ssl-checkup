# Architecture

This project is organized as a small CLI with a dedicated runtime engine:

- `ssl_checkup/cli.py`: argument parsing and argument validation.
- `ssl_checkup/main.py`: entrypoint wiring, target collection, output redirection.
- `ssl_checkup/engine.py`: execution pipeline for single/batch checks, retries, JSON/human rendering, summary and exit-code policy.
- `ssl_checkup/connection.py`: socket/TLS connection and certificate retrieval.
- `ssl_checkup/parser.py`: certificate field extraction and PEM parsing helpers.
- `ssl_checkup/display.py` and `ssl_checkup/formatting.py`: human-readable formatting.
- `ssl_checkup/exceptions.py`: standardized error messages and exit-code mapping.

## Data flow

1. Parse args and validate (`cli.py`).
2. Expand targets from positional input and `--input` (`main.py`).
3. Build engine dependencies (`main.py`).
4. Execute targets with retries and optional concurrency (`engine.py`).
5. Render JSON or human output (`engine.py` + display modules).
6. Compute a consistent final exit code (`engine.py`).

## Execution model

- Single-target and batch-target checks share one execution path in `CheckEngine`.
- `--fail-fast` runs sequentially and stops at first non-success result.
- Non-fail-fast mode uses `ThreadPoolExecutor` with `--workers`.
- Errors are represented as structured per-target results and mapped to exit codes once.

## Error and exit-code policy

- `0`: success or non-policy mode success.
- `1`: warning threshold reached (policy mode).
- `2`: critical/expired (policy mode).
- `10`: operational errors (DNS/socket/SSL/general target failures).
- `130`: keyboard interrupt.

Error-formatting helpers in `exceptions.py` return exit codes instead of terminating directly; process termination is handled at the CLI boundary in `main.py`.
