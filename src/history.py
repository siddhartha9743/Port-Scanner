import json
from pathlib import Path
from typing import Any


from pathlib import Path
import json


def save_scan_history(path, scan_metadata, summary):
    history_path = Path(path)

    history_path.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "scan": scan_metadata,
        "summary": summary,
    }

    with history_path.open("a", encoding="utf-8") as handle:
        json.dump(record, handle)
        handle.write("\n")

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
