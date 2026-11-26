from collections.abc import Callable

from .models import Settings


def backoff(settings: Settings, failed_attempt: int, draw: Callable[[], float]) -> float:
    """First failed attempt is one. Jitter samples downward within the capped delay."""
    if not 1 <= failed_attempt <= settings.attempts:
        raise ValueError("Invalid attempt number")
    cap = min(settings.backoff_cap, settings.backoff_base * (1 << (failed_attempt - 1)))
    if not settings.jitter or not cap:
        return cap
    sample = draw()
    if not 0 <= sample <= 1:
        raise ValueError("Random sample must be in [0, 1]")
    return cap * (1 - settings.jitter + settings.jitter * sample)
