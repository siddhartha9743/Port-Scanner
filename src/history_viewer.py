
from typing import Any


def format_history(
    records: list[dict[str, Any]],
) -> str:
    """
    Format scan history records as a readable table.
    """

    if not records:
        return "No scan history found."

    lines = []

    lines.append(
        f"{'#':<5}"
        f"{'TARGET':<22}"
        f"{'PORTS':<8}"
        f"{'OPEN':<7}"
        f"{'CLOSED':<8}"
        f"{'TIMEOUT':<9}"
        f"{'DURATION':<10}"
        f"{'STARTED'}"
    )

    lines.append("-" * 100)

    for index, record in enumerate(records, start=1):
        scan = record.get("scan", {})
        summary = record.get("summary", {})

        target = str(
            scan.get("target", "UNKNOWN")
        )

        ports = scan.get(
            "ports_scanned",
            0,
        )

        open_count = summary.get(
            "open",
            0,
        )

        closed_count = summary.get(
            "closed",
            0,
        )

        timeout_count = summary.get(
            "timeout",
            0,
        )

        duration = scan.get(
            "duration_seconds",
            0,
        )

        started = str(
            scan.get(
                "started_at",
                "UNKNOWN",
            )
        )

        lines.append(
            f"{index:<5}"
            f"{target:<22}"
            f"{ports:<8}"
            f"{open_count:<7}"
            f"{closed_count:<8}"
            f"{timeout_count:<9}"
            f"{str(duration) + 's':<10}"
            f"{started}"
        )

    return "\n".join(lines)
