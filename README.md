# Port Scanner

A concurrent TCP port scanner written in Python.

## Features

- Concurrent TCP port scanning
- Individual ports and port ranges
- Configurable worker count
- Configurable TCP timeout
- Quick, standard, and full scan profiles
- Table, JSON, and CSV output
- Open-port filtering
- Scan history stored as JSONL
- Scan history viewer
- JSON configuration files
- Configuration validation
- Automated test suite

## Requirements

- Python 3.10+
- pytest for running tests

The scanner itself uses only Python's standard library.

## Project Structure

```text
port-scanner/
├── README.md
├── src/
│   ├── __init__.py
│   ├── config.py
│   ├── history.py
│   ├── history_viewer.py
│   ├── main.py
│   ├── profiles.py
│   ├── reporting.py
│   ├── scanner.py
│   └── services.py
└── tests/
    └── test_scanner.py
