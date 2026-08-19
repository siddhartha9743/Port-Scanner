from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    ports: str
    timeout: float
    workers: int
    description: str


PROFILES = {
    "quick": ScanProfile(
        name="quick",
        ports="21,22,23,25,53,80,110,143,443,3306,5432,6379,8080,8443",
        timeout=0.5,
        workers=50,
        description="Common TCP service ports",
    ),
    "standard": ScanProfile(
        name="standard",
        ports="1-1024",
        timeout=1.0,
        workers=50,
        description="Well-known TCP ports",
    ),
    "full": ScanProfile(
        name="full",
        ports="1-65535",
        timeout=1.0,
        workers=100,
        description="All TCP ports",
    ),
}


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"Unknown scan profile: {name}")


def list_profiles() -> list[ScanProfile]:
    return list(PROFILES.values())
