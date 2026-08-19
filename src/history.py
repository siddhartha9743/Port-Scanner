import json
from pathlib import Path
from typing import Any


def save_scan_history(
    path: str,
    scan_data: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    """
    Append one scan record to a JSON Lines history file.
    """
    record = {
        "scan": scan_data,
        "summary": summary,
    }

    history_path = Path(path)

    with history_path.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
        )
        file.write("\n")


def load_scan_history(
    path: str,
) -> list[dict[str, Any]]:
    """
    Load all scan records from a JSON Lines history file.

    Missing history files return an empty list.
    """
    history_path = Path(path)

    if not history_path.exists():
        return []

    records = []

    with history_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            records.append(
                json.loads(line)
            )

    return records
