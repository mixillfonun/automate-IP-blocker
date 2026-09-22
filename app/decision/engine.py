from enum import Enum


class Decision(str, Enum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    BLOCK = "BLOCK"


def decide(
    score: int,
    monitor_threshold: int = 80,
    block_threshold: int = 90,
) -> Decision:

    if score >= block_threshold:
        return Decision.BLOCK

    if score >= monitor_threshold:
        return Decision.MONITOR

    return Decision.ALLOW
