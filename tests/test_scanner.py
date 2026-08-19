import socket
import threading

import pytest
import sys
import json
from src.main import parse_ports
from src.profiles import get_profile, list_profiles
from src.scanner import PortStatus, grab_banner, scan_port, scan_ports
from src.services import get_service_name


def start_test_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    port = server.getsockname()[1]

    def accept_connection():
        connection, _ = server.accept()
        connection.close()
        server.close()

    thread = threading.Thread(
        target=accept_connection,
        daemon=True,
    )
    thread.start()

    return port


def start_banner_server(banner: str):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    port = server.getsockname()[1]

    def accept_connection():
        connection, _ = server.accept()

        try:
            connection.sendall(banner.encode("utf-8"))
        finally:
            connection.close()
            server.close()

    thread = threading.Thread(
        target=accept_connection,
        daemon=True,
    )
    thread.start()

    return port


def test_open_port():
    port = start_test_server()

    assert scan_port("127.0.0.1", port) == PortStatus.OPEN


def test_closed_port():
    temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp_socket.bind(("127.0.0.1", 0))

    port = temp_socket.getsockname()[1]
    temp_socket.close()

    assert scan_port("127.0.0.1", port) == PortStatus.CLOSED


def test_grab_banner():
    port = start_banner_server("TEST-SERVICE 1.0\r\n")

    assert grab_banner("127.0.0.1", port) == "TEST-SERVICE 1.0"


def test_grab_banner_timeout():
    port = start_test_server()

    assert grab_banner("127.0.0.1", port, timeout=0.01) == ""


def test_parse_single_port():
    assert parse_ports("22") == [22]


def test_parse_multiple_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_range():
    assert parse_ports("1-5") == [1, 2, 3, 4, 5]


def test_parse_mixed_ports():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_duplicate_ports():
    assert parse_ports("80,80,81") == [80, 81]


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "65536",
        "100-50",
        "abc",
        "80-",
        "-80",
        "",
    ],
)
def test_invalid_ports(value):
    with pytest.raises(ValueError):
        parse_ports(value)


def test_known_service():
    assert get_service_name(22) == "SSH"


def test_http_alt_service():
    assert get_service_name(8080) == "HTTP-ALT"


def test_unknown_service():
    assert get_service_name(9999) == "UNKNOWN"


def test_invalid_timeout():
    with pytest.raises(ValueError):
        scan_ports(
            "127.0.0.1",
            [80],
            timeout=0,
        )


def test_quick_profile():
    profile = get_profile("quick")

    assert profile.name == "quick"
    assert profile.ports == (
        "21,22,23,25,53,80,110,143,443,3306,5432,6379,8080,8443"
    )
    assert profile.timeout == 0.5
    assert profile.workers == 50


def test_standard_profile():
    profile = get_profile("standard")

    assert profile.name == "standard"
    assert profile.ports == "1-1024"
    assert profile.timeout == 1.0
    assert profile.workers == 50


def test_full_profile():
    profile = get_profile("full")

    assert profile.name == "full"
    assert profile.ports == "1-65535"
    assert profile.timeout == 1.0
    assert profile.workers == 100


def test_list_profiles():
    profiles = list_profiles()

    assert [profile.name for profile in profiles] == [
        "quick",
        "standard",
        "full",
    ]


def test_unknown_profile():
    with pytest.raises(ValueError):
        get_profile("does-not-exist")
def test_resolve_target_ip():
    from src.main import resolve_target

    assert resolve_target("127.0.0.1") == "127.0.0.1"


def test_resolve_invalid_target():
    from src.main import resolve_target

    with pytest.raises(ValueError):
        resolve_target(
            "definitely-not-a-real-host-12345"
        )


def test_max_ports_constant():
    from src.main import MAX_PORTS

    assert MAX_PORTS == 10_000
def test_utc_timestamp():
    from src.main import utc_timestamp

    timestamp = utc_timestamp()

    assert timestamp.endswith("+00:00")
    assert "T" in timestamp
def test_scan_history_round_trip(tmp_path):
    from src.history import (
        load_scan_history,
        save_scan_history,
    )

    history_file = tmp_path / "history.jsonl"

    scan_data = {
        "target": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "ports_scanned": 2,
    }

    summary = {
        "open": 1,
        "closed": 1,
        "timeout": 0,
    }

    save_scan_history(
        str(history_file),
        scan_data,
        summary,
    )

    records = load_scan_history(
        str(history_file)
    )

    assert len(records) == 1
    assert records[0]["scan"]["target"] == "127.0.0.1"
    assert records[0]["scan"]["ports_scanned"] == 2
    assert records[0]["summary"]["open"] == 1


def test_load_missing_history(tmp_path):
    from src.history import load_scan_history

    history_file = tmp_path / "missing.jsonl"

    assert load_scan_history(
        str(history_file)
    ) == []
def test_config_rejects_zero_workers():
    from src.config import create_config

    with pytest.raises(ValueError, match="workers"):
        create_config(workers=0)


def test_config_rejects_negative_timeout():
    from src.config import create_config

    with pytest.raises(ValueError, match="timeout"):
        create_config(timeout=-1)


def test_config_rejects_zero_max_ports():
    from src.config import create_config

    with pytest.raises(ValueError, match="max_ports"):
        create_config(max_ports=0)
def test_load_config_from_json(tmp_path):
    from src.config import load_config

    config_file = tmp_path / "config.json"

    config_file.write_text(
        '{"workers": 10, "timeout": 0.5, "max_ports": 5000}',
        encoding="utf-8",
    )

    config = load_config(str(config_file))

    assert config.workers == 10
    assert config.timeout == 0.5
    assert config.max_ports == 5000


def test_load_config_missing_file():
    from src.config import load_config

    with pytest.raises(
        ValueError,
        match="Configuration file not found",
    ):
        load_config("/tmp/does-not-exist-port-scanner.json")


def test_load_config_invalid_json(tmp_path):
    from src.config import load_config

    config_file = tmp_path / "invalid.json"

    config_file.write_text(
        "{not valid json",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid configuration JSON",
    ):
        load_config(str(config_file))


def test_load_config_invalid_values(tmp_path):
    from src.config import load_config

    config_file = tmp_path / "invalid-values.json"

    config_file.write_text(
        '{"workers": 0, "timeout": 1.0, "max_ports": 10000}',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="workers must be at least 1",
    ):
        load_config(str(config_file))
def test_cli_requires_target_or_history(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = ["main.py"]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "target is required unless --view-history is used" in captured.err


def test_cli_requires_ports_or_profile(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = ["main.py", "127.0.0.1"]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "one of --ports or --profile is required" in captured.err


def test_cli_rejects_invalid_workers(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--workers",
        "0",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "workers must be at least 1" in captured.err


def test_cli_rejects_invalid_timeout(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--timeout",
        "0",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "timeout must be greater than 0" in captured.err


def test_cli_requires_output_for_csv(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--format",
        "csv",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "--output is required when using --format csv" in captured.err


def test_cli_rejects_ports_and_profile_together(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--profile",
        "quick",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "--ports and --profile cannot be used together" in captured.err
def test_cli_json_output(capsys):
    from src.main import main
    import json
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--format",
        "json",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert output["scan"]["target"] == "127.0.0.1"
    assert output["scan"]["ports_scanned"] == 1
    assert output["summary"]["closed"] == 1
    assert output["results"][0]["port"] == 22


def test_cli_csv_output(tmp_path, capsys):
    from src.main import main
    import sys

    output_file = tmp_path / "scan.csv"

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--format",
        "csv",
        "--output",
        str(output_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert output_file.exists()
    assert "CSV report written to:" in captured.out

    content = output_file.read_text()
    assert "22" in content
    assert "CLOSED" in content


def test_cli_open_only(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--open-only",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "PORT" in captured.out
    assert "22      CLOSED" not in captured.out
    assert "Open: 0" in captured.out


def test_cli_quick_profile(capsys):
    from src.main import main
    import sys

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--profile",
        "quick",
        "--format",
        "json",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    import json
    output = json.loads(captured.out)

    assert output["scan"]["profile"] == "quick"
    assert output["scan"]["ports_scanned"] == 14
def test_cli_writes_history(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "history.jsonl"

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--history",
        str(history_file),
        "--format",
        "json",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    capsys.readouterr()

    assert history_file.exists()

    lines = history_file.read_text().strip().splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])

    assert record["scan"]["target"] == "127.0.0.1"
    assert record["scan"]["ports_scanned"] == 1
    assert record["summary"]["open"] == 0
    assert record["summary"]["closed"] == 1
    assert record["summary"]["timeout"] == 0


def test_cli_appends_history(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "history.jsonl"

    old_argv = sys.argv

    try:
        sys.argv = [
            "main.py",
            "127.0.0.1",
            "--ports",
            "22",
            "--history",
            str(history_file),
        ]

        main()
        capsys.readouterr()

        sys.argv = [
            "main.py",
            "127.0.0.1",
            "--ports",
            "80",
            "--history",
            str(history_file),
        ]

        main()
        capsys.readouterr()

    finally:
        sys.argv = old_argv

    lines = history_file.read_text().strip().splitlines()

    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["scan"]["ports_scanned"] == 1
    assert second["scan"]["ports_scanned"] == 1
    assert first["scan"]["target"] == "127.0.0.1"
    assert second["scan"]["target"] == "127.0.0.1"


def test_cli_view_history(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "resolved_ip": "127.0.0.1",
            "profile": None,
            "started_at": "2026-08-19T00:00:00+00:00",
            "finished_at": "2026-08-19T00:00:01+00:00",
            "duration_seconds": 0.001,
            "ports_scanned": 2,
            "workers": 50,
            "timeout_seconds": 1.0,
        },
        "summary": {
            "open": 0,
            "closed": 2,
            "timeout": 0,
        },
    }

    history_file.write_text(json.dumps(record) + "\n")

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "127.0.0.1" in captured.out
    assert "2" in captured.out


def test_cli_view_missing_history(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "missing-history.jsonl"

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "No scan history found." in captured.out
def test_cli_view_empty_history(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "empty-history.jsonl"
    history_file.write_text("")

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "No scan history found." in captured.out


def test_cli_view_multiple_history_records(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "history.jsonl"

    records = [
        {
            "scan": {
                "target": "127.0.0.1",
                "resolved_ip": "127.0.0.1",
                "profile": None,
                "started_at": "2026-08-19T00:00:00+00:00",
                "finished_at": "2026-08-19T00:00:01+00:00",
                "duration_seconds": 0.001,
                "ports_scanned": 1,
                "workers": 50,
                "timeout_seconds": 1.0,
            },
            "summary": {
                "open": 0,
                "closed": 1,
                "timeout": 0,
            },
        },
        {
            "scan": {
                "target": "localhost",
                "resolved_ip": "127.0.0.1",
                "profile": "quick",
                "started_at": "2026-08-19T00:01:00+00:00",
                "finished_at": "2026-08-19T00:01:01+00:00",
                "duration_seconds": 0.002,
                "ports_scanned": 14,
                "workers": 50,
                "timeout_seconds": 0.5,
            },
            "summary": {
                "open": 1,
                "closed": 13,
                "timeout": 0,
            },
        },
    ]

    history_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n"
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "127.0.0.1" in captured.out
    assert "localhost" in captured.out
    assert "14" in captured.out


def test_cli_history_creates_missing_parent_directory(tmp_path, capsys):
    from src.main import main

    history_file = tmp_path / "nested" / "history.jsonl"

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "127.0.0.1",
        "--ports",
        "22",
        "--history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert history_file.exists()
    assert "Scan history appended to:" in captured.out

def test_cli_view_history_rejects_corrupt_json(tmp_path, capsys):
    from src.main import main
    import sys

    history_file = tmp_path / "corrupt-history.jsonl"
    history_file.write_text(
        '{"scan": {"target": "127.0.0.1"}\n',
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "Expecting" in captured.err or "JSON" in captured.err


def test_cli_view_history_rejects_invalid_json_line(tmp_path, capsys):
    from src.main import main
    import sys

    history_file = tmp_path / "history.jsonl"
    history_file.write_text(
        "this is not valid json\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "Expecting" in captured.err or "JSON" in captured.err
def test_cli_view_history_missing_scan_section(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "summary": {
            "open": 0,
            "closed": 1,
            "timeout": 0,
        }
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "UNKNOWN" in captured.out
    assert "1" in captured.out


def test_cli_view_history_missing_summary_section(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "ports_scanned": 1,
        }
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "127.0.0.1" in captured.out
    assert "1" in captured.out


def test_cli_view_history_invalid_record_structure(tmp_path, capsys):
    from src.main import main
    import sys

    history_file = tmp_path / "history.jsonl"

    history_file.write_text(
        "[]\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        with pytest.raises(AttributeError):
            main()
    finally:
        sys.argv = old_argv


def test_cli_view_history_empty_file(tmp_path, capsys):
    from src.main import main
    import sys

    history_file = tmp_path / "empty-history.jsonl"
    history_file.write_text("", encoding="utf-8")

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "No scan history found." in captured.out

def test_cli_view_history_empty_file(tmp_path, capsys):
    from src.main import main
    import sys

    history_file = tmp_path / "empty-history.jsonl"
    history_file.write_text("", encoding="utf-8")

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "No scan history found." in captured.out
def test_history_viewer_formats_multiple_records():
    from src.history_viewer import format_history

    records = [
        {
            "scan": {
                "target": "127.0.0.1",
                "ports_scanned": 2,
                "started_at": "2026-08-19T00:00:00+00:00",
                "duration_seconds": 0.1,
            },
            "summary": {
                "open": 1,
                "closed": 1,
                "timeout": 0,
            },
        },
        {
            "scan": {
                "target": "localhost",
                "ports_scanned": 3,
                "started_at": "2026-08-19T00:01:00+00:00",
                "duration_seconds": 0.2,
            },
            "summary": {
                "open": 2,
                "closed": 1,
                "timeout": 0,
            },
        },
    ]

    output = format_history(records)

    assert "127.0.0.1" in output
    assert "localhost" in output
    assert "1" in output
    assert "2" in output


def test_history_viewer_empty_history():
    from src.history_viewer import format_history

    output = format_history([])

    assert output == "No scan history found."


def test_history_viewer_handles_missing_fields():
    from src.history_viewer import format_history

    records = [
        {
            "scan": {},
            "summary": {},
        }
    ]

    output = format_history(records)

    assert "UNKNOWN" in output
    assert "0" in output


def test_history_viewer_handles_multiple_history_records():
    from src.history_viewer import format_history

    records = [
        {
            "scan": {
                "target": "192.168.1.1",
                "ports_scanned": 10,
                "started_at": "2026-08-19T00:00:00+00:00",
                "duration_seconds": 1.5,
            },
            "summary": {
                "open": 2,
                "closed": 7,
                "timeout": 1,
            },
        },
        {
            "scan": {
                "target": "10.0.0.1",
                "ports_scanned": 5,
                "started_at": "2026-08-19T00:05:00+00:00",
                "duration_seconds": 0.5,
            },
            "summary": {
                "open": 0,
                "closed": 5,
                "timeout": 0,
            },
        },
    ]

    output = format_history(records)

    assert "192.168.1.1" in output
    assert "10.0.0.1" in output
    assert "1.5s" in output
    assert "0.5s" in output
def test_cli_view_history_prints_header(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "ports_scanned": 2,
            "started_at": "2026-08-19T00:00:00+00:00",
            "duration_seconds": 0.1,
        },
        "summary": {
            "open": 1,
            "closed": 1,
            "timeout": 0,
        },
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "TARGET" in captured.out
    assert "PORTS" in captured.out
    assert "OPEN" in captured.out
    assert "CLOSED" in captured.out
    assert "TIMEOUT" in captured.out
    assert "DURATION" in captured.out
    assert "STARTED" in captured.out


def test_cli_view_history_prints_record_values(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "192.168.1.10",
            "ports_scanned": 5,
            "started_at": "2026-08-19T00:00:00+00:00",
            "duration_seconds": 1.5,
        },
        "summary": {
            "open": 2,
            "closed": 2,
            "timeout": 1,
        },
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "192.168.1.10" in captured.out
    assert "5" in captured.out
    assert "2" in captured.out
    assert "1" in captured.out
    assert "1.5s" in captured.out


def test_cli_view_history_prints_multiple_records(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    records = [
        {
            "scan": {
                "target": "127.0.0.1",
                "ports_scanned": 1,
                "started_at": "2026-08-19T00:00:00+00:00",
                "duration_seconds": 0.1,
            },
            "summary": {
                "open": 0,
                "closed": 1,
                "timeout": 0,
            },
        },
        {
            "scan": {
                "target": "localhost",
                "ports_scanned": 3,
                "started_at": "2026-08-19T00:01:00+00:00",
                "duration_seconds": 0.3,
            },
            "summary": {
                "open": 1,
                "closed": 2,
                "timeout": 0,
            },
        },
    ]

    history_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "127.0.0.1" in captured.out
    assert "localhost" in captured.out
    assert "1" in captured.out
    assert "2" in captured.out
    assert "3" in captured.out
# ============================================================
# Phase 26 - History Limit Tests
# ============================================================

def test_cli_view_history_limit(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    records = []

    for index in range(5):
        records.append(
            {
                "scan": {
                    "target": f"192.168.1.{index + 1}",
                    "ports_scanned": index + 1,
                    "started_at": f"2026-08-19T00:00:0{index}+00:00",
                    "duration_seconds": 0.001,
                },
                "summary": {
                    "open": index,
                    "closed": 1,
                    "timeout": 0,
                },
            }
        )

    history_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
        "--limit",
        "2",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "192.168.1.4" in captured.out
    assert "192.168.1.5" in captured.out
    assert "192.168.1.1" not in captured.out
    assert "192.168.1.2" not in captured.out
    assert "192.168.1.3" not in captured.out


def test_cli_view_history_limit_one(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    records = [
        {
            "scan": {
                "target": "10.0.0.1",
                "ports_scanned": 1,
                "started_at": "2026-08-19T00:00:00+00:00",
                "duration_seconds": 0.001,
            },
            "summary": {
                "open": 1,
                "closed": 0,
                "timeout": 0,
            },
        },
        {
            "scan": {
                "target": "10.0.0.2",
                "ports_scanned": 2,
                "started_at": "2026-08-19T00:00:01+00:00",
                "duration_seconds": 0.002,
            },
            "summary": {
                "open": 0,
                "closed": 2,
                "timeout": 0,
            },
        },
    ]

    history_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
        "--limit",
        "1",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "10.0.0.2" in captured.out
    assert "10.0.0.1" not in captured.out


def test_cli_view_history_limit_larger_than_history(
    tmp_path,
    capsys,
):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "ports_scanned": 1,
            "started_at": "2026-08-19T00:00:00+00:00",
            "duration_seconds": 0.001,
        },
        "summary": {
            "open": 0,
            "closed": 1,
            "timeout": 0,
        },
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
        "--limit",
        "100",
    ]

    try:
        main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "127.0.0.1" in captured.out


def test_cli_view_history_rejects_zero_limit(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "ports_scanned": 1,
            "started_at": "2026-08-19T00:00:00+00:00",
            "duration_seconds": 0.001,
        },
        "summary": {
            "open": 0,
            "closed": 1,
            "timeout": 0,
        },
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
        "--limit",
        "0",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "--limit must be at least 1" in captured.err


def test_cli_view_history_rejects_negative_limit(tmp_path, capsys):
    from src.main import main
    import json
    import sys

    history_file = tmp_path / "history.jsonl"

    record = {
        "scan": {
            "target": "127.0.0.1",
            "ports_scanned": 1,
            "started_at": "2026-08-19T00:00:00+00:00",
            "duration_seconds": 0.001,
        },
        "summary": {
            "open": 0,
            "closed": 1,
            "timeout": 0,
        },
    }

    history_file.write_text(
        json.dumps(record) + "\n",
        encoding="utf-8",
    )

    old_argv = sys.argv
    sys.argv = [
        "main.py",
        "--view-history",
        str(history_file),
        "--limit",
        "-5",
    ]

    try:
        with pytest.raises(SystemExit):
            main()
    finally:
        sys.argv = old_argv

    captured = capsys.readouterr()

    assert "--limit must be at least 1" in captured.err
