from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class ScanConfig:
    workers: int = 50
    timeout: float = 1.0
    max_ports: int = 10000

    def validate(self) -> None:
        if self.workers < 1:
            raise ValueError("workers must be at least 1")

        if self.timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        if self.max_ports < 1:
            raise ValueError("max_ports must be at least 1")


DEFAULT_CONFIG = ScanConfig()


def create_config(
    workers: int = 50,
    timeout: float = 1.0,
    max_ports: int = 10000,
) -> ScanConfig:
    config = ScanConfig(
        workers=workers,
        timeout=timeout,
        max_ports=max_ports,
    )

    config.validate()

    return config


def load_config(path: str | None = None) -> ScanConfig:
    """
    Load scan configuration from a JSON file.

    If no path is supplied, return the default configuration.
    """

    if path is None:
        return DEFAULT_CONFIG

    config_path = Path(path)

    if not config_path.exists():
        raise ValueError(
            f"Configuration file not found: {path}"
        )

    try:
        with config_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid configuration JSON: {exc}"
        ) from exc
    except OSError as exc:
        raise ValueError(
            f"Unable to read configuration file: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "Configuration file must contain a JSON object"
        )

    try:
        workers = data.get(
            "workers",
            DEFAULT_CONFIG.workers,
        )

        timeout = data.get(
            "timeout",
            DEFAULT_CONFIG.timeout,
        )

        max_ports = data.get(
            "max_ports",
            DEFAULT_CONFIG.max_ports,
        )

        config = create_config(
            workers=int(workers),
            timeout=float(timeout),
            max_ports=int(max_ports),
        )

    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid configuration values: {exc}"
        ) from exc

    return config
