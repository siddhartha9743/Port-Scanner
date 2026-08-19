import socket
from concurrent.futures import ThreadPoolExecutor
from enum import Enum


class PortStatus(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    TIMEOUT = "TIMEOUT"


def scan_port(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> PortStatus:
    """
    Attempt a TCP connection to target:port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            if result == 0:
                return PortStatus.OPEN

            return PortStatus.CLOSED

    except socket.timeout:
        return PortStatus.TIMEOUT

    except OSError:
        return PortStatus.CLOSED


def grab_banner(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> str:
    """
    Connect to an open TCP service and attempt to read its banner.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target, port))

            data = sock.recv(1024)

            return data.decode("utf-8", errors="replace").strip()

    except (socket.timeout, OSError):
        return ""


def scan_ports(
    target: str,
    ports: list[int],
    timeout: float = 1.0,
    workers: int = 50,
) -> dict[int, PortStatus]:
    """
    Scan multiple TCP ports concurrently.
    """
    if workers < 1:
        raise ValueError("workers must be at least 1")

    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")

    results: dict[int, PortStatus] = {}

    def scan_one(port: int) -> tuple[int, PortStatus]:
        return port, scan_port(target, port, timeout)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for port, status in executor.map(scan_one, ports):
            results[port] = status

    return results
