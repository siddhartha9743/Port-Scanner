import argparse
import json
import socket
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

try:
    from .config import DEFAULT_CONFIG, create_config, load_config
    from .history import load_scan_history, save_scan_history
    from .history_viewer import format_history
    from .profiles import get_profile, list_profiles
    from .reporting import write_csv
    from .scanner import PortStatus, scan_ports
    from .services import get_service_name
except ImportError:
    from config import DEFAULT_CONFIG, create_config, load_config
    from history import load_scan_history, save_scan_history
    from history_viewer import format_history
    from profiles import get_profile, list_profiles
    from reporting import write_csv
    from scanner import PortStatus, scan_ports
    from services import get_service_name


MAX_PORTS = DEFAULT_CONFIG.max_ports


def utc_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


def parse_ports(port_spec: str) -> list[int]:
    ports: set[int] = set()

    for part in port_spec.split(","):
        part = part.strip()

        if not part:
            raise ValueError("Empty port value")

        if "-" in part:
            pieces = part.split("-")

            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {part}")

            try:
                start = int(pieces[0])
                end = int(pieces[1])
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")

            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")

            ports.update(range(start, end + 1))

        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port: {part}")

            if not 1 <= port <= 65535:
                raise ValueError(
                    f"Port must be between 1 and 65535: {port}"
                )

            ports.add(port)

    if not ports:
        raise ValueError("No ports specified")

    if len(ports) > MAX_PORTS:
        raise ValueError(
            f"Port scan contains {len(ports)} ports; "
            f"maximum allowed is {MAX_PORTS}"
        )

    return sorted(ports)


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Unable to resolve target: {target}")


@dataclass
class ScanRecord:
    port: int
    status: str
    service: str
    banner: str


def build_records(results: dict) -> list[ScanRecord]:
    records = []

    for port in sorted(results):
        result = results[port]

        if hasattr(result, "status"):
            status = result.status
            banner = result.banner
        else:
            status = result
            banner = ""

        if hasattr(status, "value"):
            status_value = status.value
        else:
            status_value = str(status)

        records.append(
            ScanRecord(
                port=port,
                status=status_value,
                service=get_service_name(port),
                banner=banner,
            )
        )

    return records


def build_summary(records: list[ScanRecord]) -> dict:
    return {
        "open": sum(
            1
            for record in records
            if record.status == PortStatus.OPEN.value
        ),
        "closed": sum(
            1
            for record in records
            if record.status == PortStatus.CLOSED.value
        ),
        "timeout": sum(
            1
            for record in records
            if record.status == PortStatus.TIMEOUT.value
        ),
    }


def build_scan_metadata(
    target: str,
    resolved_ip: str,
    profile_name: str | None,
    started_at: str,
    finished_at: str,
    elapsed: float,
    records: list[ScanRecord],
    workers: int,
    timeout: float,
) -> dict:
    return {
        "target": target,
        "resolved_ip": resolved_ip,
        "profile": profile_name,
        "started_at": started_at,
        "finished_at": finished_at,
        "duration_seconds": round(elapsed, 4),
        "ports_scanned": len(records),
        "workers": workers,
        "timeout_seconds": timeout,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Concurrent TCP port scanner"
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="IP address or hostname to scan",
    )

    parser.add_argument(
        "--ports",
        help="Ports: 22 | 22,80,443 | 1-1024",
    )

    parser.add_argument(
        "--profile",
        choices=sorted(
            profile.name
            for profile in list_profiles()
        ),
        help="Use a predefined scan profile",
    )

    parser.add_argument(
        "--config",
        help="Load scanner configuration from a JSON file",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Maximum concurrent workers",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="TCP connection timeout in seconds",
    )

    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Show only open ports",
    )

    parser.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="Output format",
    )

    parser.add_argument(
        "--output",
        help="Output file for CSV format",
    )

    parser.add_argument(
        "--history",
        help="Append scan metadata to a JSONL history file",
    )

    parser.add_argument(
        "--view-history",
        metavar="FILE",
        help="Display saved scan history",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit displayed history records",
    )

    args = parser.parse_args()

    # ---------------------------------------------------------
    # HISTORY VIEWER MODE
    # ---------------------------------------------------------

    if args.view_history:
        try:
            records = load_scan_history(args.view_history)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))

        if args.limit is not None:
            if args.limit < 1:
                parser.error("--limit must be at least 1")

            records = records[-args.limit:]

        print(format_history(records))
        return

    # ---------------------------------------------------------
    # BASIC ARGUMENT VALIDATION
    # ---------------------------------------------------------

    if not args.target:
        parser.error(
            "target is required unless --view-history is used"
        )

    if args.ports and args.profile:
        parser.error(
            "--ports and --profile cannot be used together"
        )

    if not args.ports and not args.profile:
        parser.error(
            "one of --ports or --profile is required"
        )

    # ---------------------------------------------------------
    # LOAD BASE CONFIGURATION
    # ---------------------------------------------------------

    if args.config:
        try:
            file_config = load_config(args.config)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        file_config = DEFAULT_CONFIG

    # ---------------------------------------------------------
    # PROFILE / CLI CONFIGURATION
    # ---------------------------------------------------------

    profile_name = None

    if args.profile:
        profile = get_profile(args.profile)

        if profile is None:
            parser.error(
                f"Unknown profile: {args.profile}"
            )

        profile_name = profile.name
        port_spec = profile.ports

        workers = (
            args.workers
            if args.workers is not None
            else profile.workers
        )

        timeout = (
            args.timeout
            if args.timeout is not None
            else profile.timeout
        )

    else:
        port_spec = args.ports

        workers = (
            args.workers
            if args.workers is not None
            else file_config.workers
        )

        timeout = (
            args.timeout
            if args.timeout is not None
            else file_config.timeout
        )

    # CLI values override configuration-file values.
    try:
        config = create_config(
            workers=workers,
            timeout=timeout,
            max_ports=file_config.max_ports,
        )
    except ValueError as exc:
        parser.error(str(exc))

    workers = config.workers
    timeout = config.timeout

    # ---------------------------------------------------------
    # TARGET / PORT PARSING
    # ---------------------------------------------------------

    try:
        target_ip = resolve_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        ports = parse_ports(port_spec)

        if len(ports) > config.max_ports:
            raise ValueError(
                f"Port scan contains {len(ports)} ports; "
                f"maximum allowed is {config.max_ports}"
            )

    except ValueError as exc:
        parser.error(str(exc))

    # ---------------------------------------------------------
    # SCAN
    # ---------------------------------------------------------

    started_at = utc_timestamp()
    start_time = time.perf_counter()

    results = scan_ports(
        target_ip,
        ports,
        timeout=timeout,
        workers=workers,
    )

    elapsed = time.perf_counter() - start_time
    finished_at = utc_timestamp()

    # ---------------------------------------------------------
    # RESULTS
    # ---------------------------------------------------------

    records = build_records(results)
    summary = build_summary(records)

    scan_metadata = build_scan_metadata(
        target=args.target,
        resolved_ip=target_ip,
        profile_name=profile_name,
        started_at=started_at,
        finished_at=finished_at,
        elapsed=elapsed,
        records=records,
        workers=workers,
        timeout=timeout,
    )

    # ---------------------------------------------------------
    # HISTORY
    # ---------------------------------------------------------

    if args.history:
        try:
            save_scan_history(
                args.history,
                scan_metadata,
                summary,
            )
        except OSError as exc:
            parser.error(str(exc))

        print(
            f"Scan history appended to: {args.history}"
        )

    # ---------------------------------------------------------
    # CSV
    # ---------------------------------------------------------

    if args.format == "csv":
        if not args.output:
            parser.error(
                "--output is required when using --format csv"
            )

        try:
            write_csv(
                args.output,
                records,
            )
        except OSError as exc:
            parser.error(str(exc))

        print(
            f"CSV report written to: {args.output}"
        )
        return

    # ---------------------------------------------------------
    # JSON
    # ---------------------------------------------------------

    if args.format == "json":
        visible_records = [
            record
            for record in records
            if (
                not args.open_only
                or record.status == PortStatus.OPEN.value
            )
        ]

        output = {
            "scan": scan_metadata,
            "summary": summary,
            "results": [
                asdict(record)
                for record in visible_records
            ],
        }

        print(
            json.dumps(
                output,
                indent=2,
            )
        )
        return

    # ---------------------------------------------------------
    # TABLE
    # ---------------------------------------------------------

    visible_records = [
        record
        for record in records
        if (
            not args.open_only
            or record.status == PortStatus.OPEN.value
        )
    ]

    print(f"Target: {args.target}")
    print(f"Resolved IP: {target_ip}")
    print(f"Started: {started_at}")
    print(f"Finished: {finished_at}")
    print(f"Ports scanned: {len(records)}")
    print(f"Workers: {workers}")
    print(f"Timeout: {timeout:.2f}s")
    print()

    print(
        f"{'PORT':<8}"
        f"{'STATUS':<10}"
        f"{'SERVICE':<15}"
        f"BANNER"
    )

    print("-" * 70)

    for record in visible_records:
        print(
            f"{record.port:<8}"
            f"{record.status:<10}"
            f"{record.service:<15}"
            f"{record.banner}"
        )

    print()
    print("SUMMARY")
    print(f"Open: {summary['open']}")
    print(f"Closed: {summary['closed']}")
    print(f"Timeout: {summary['timeout']}")
    print(f"Duration: {elapsed:.3f}s")


if __name__ == "__main__":
    main()
