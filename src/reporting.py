import csv
import json
from dataclasses import asdict
from pathlib import Path


def records_to_dicts(records) -> list[dict]:
    return [asdict(record) for record in records]


def write_json(
    path: str,
    data: dict,
) -> None:
    output_path = Path(path)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

        file.write("\n")


def write_csv(
    path: str,
    records,
) -> None:
    output_path = Path(path)

    rows = records_to_dicts(records)

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "port",
                "status",
                "service",
                "banner",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)
