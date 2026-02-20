from dataclasses import dataclass

@dataclass(frozen=True)
class SnmpProfile:
    community: str
    timeout_s: int = 2
    retries: int = 1
