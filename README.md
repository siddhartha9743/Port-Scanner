# Port Scanner

A concurrent TCP port scanner written in Python with configurable scanning, multiple output formats, scan history, and a comprehensive automated test suite.

## Features

* Concurrent TCP port scanning
* Individual ports and port ranges
* Configurable worker count
* Configurable TCP timeout
* Quick, standard, and full scan profiles
* Table output
* JSON output
* CSV output
* Open-port filtering
* Scan history stored in JSONL format
* Scan history viewer
* History record limiting with `--limit`
* History validation and corrupt-file detection
* JSON configuration files
* Configuration validation
* Service-name detection for common ports
* Comprehensive automated tests

## Requirements

* Python 3.10+
* `pytest` for running the test suite

The scanner itself uses only Python's standard library.

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/siddhartha9743/port-scanner.git
cd port-scanner
```

No third-party packages are required to run the scanner.

## Usage

Run a scan by specifying a target and ports:

```bash
python -m src.main 127.0.0.1 --ports 22
```

Scan multiple ports:

```bash
python -m src.main 127.0.0.1 --ports 22,80,443
```

Scan a port range:

```bash
python -m src.main 127.0.0.1 --ports 1-1024
```

Show only open ports:

```bash
python -m src.main 127.0.0.1 --ports 1-1024 --open-only
```

## Scan Profiles

The scanner provides predefined profiles:

```bash
python -m src.main 127.0.0.1 --profile quick
```

```bash
python -m src.main 127.0.0.1 --profile standard
```

```bash
python -m src.main 127.0.0.1 --profile full
```

## Output Formats

### Table

Table output is the default:

```bash
python -m src.main 127.0.0.1 --ports 22,80,443
```

### JSON

```bash
python -m src.main 127.0.0.1 --ports 22,80,443 --format json
```

### CSV

```bash
python -m src.main 127.0.0.1 --ports 22,80,443 --format csv --output results.csv
```

## Configuration

Worker count and timeout can be configured from the command line:

```bash
python -m src.main 127.0.0.1 --ports 22,80,443 --workers 20 --timeout 1.0
```

A JSON configuration file can also be supplied:

```bash
python -m src.main 127.0.0.1 --ports 22,80,443 --config config.json
```

## Scan History

Scan metadata can be stored in a JSONL history file:

```bash
python -m src.main 127.0.0.1 --ports 22,80,443 --history history.jsonl
```

View saved history:

```bash
python -m src.main --view-history history.jsonl
```

Limit the number of displayed records:

```bash
python -m src.main --view-history history.jsonl --limit 5
```

The limit displays the most recent records.

The limit must be at least `1`:

```bash
python -m src.main --view-history history.jsonl --limit 0
```

will be rejected.

## Testing

Run the complete test suite:

```bash
python -m pytest -q
```

The project currently contains **89 automated tests**.

A successful test run should report:

```text
89 passed
```

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
```

### Source Modules

* `scanner.py` — concurrent TCP scanning logic
* `main.py` — command-line interface and application flow
* `config.py` — configuration loading and validation
* `profiles.py` — predefined scanning profiles
* `history.py` — JSONL history storage and validation
* `history_viewer.py` — formatting saved scan history
* `reporting.py` — CSV report generation
* `services.py` — common TCP service-name lookup

## Project Status

This project is considered complete in its current scope.

The implemented functionality includes scanning, configuration, profiles, reporting, history persistence, history validation, history viewing, history limits, and automated testing.

Further development should be treated as a new version or separate project rather than continuing to add artificial development phases.
