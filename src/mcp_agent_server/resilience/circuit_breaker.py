from collections.abc import Callable, Iterator
from contextlib import contextmanager
from enum import StrEnum

from .models import CircuitOpen, Settings, TransientFailure


class State(StrEnum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Event-loop confined. No transition yields control partway through an update."""

    def __init__(self, settings: Settings, clock: Callable[[], float]) -> None:
        self.settings = settings
        self.clock = clock
        self.state = State.CLOSED
        self._generation = 0
        self._failures = 0
        self._opened_at = 0.0
        self._inflight = 0
        self._successes = 0

    def check(self) -> None:
        if self.state is State.OPEN and self.clock() - self._opened_at < self.settings.cooldown:
            raise CircuitOpen("Dependency circuit is open")
        if (
            self.state is State.HALF_OPEN
            and self._inflight + self._successes >= self.settings.probes
        ):
            raise CircuitOpen("Recovery probe capacity is full")

    def _transition(self, state: State) -> None:
        self._generation += 1
        self.state = state
        self._failures = self._inflight = self._successes = 0
        if state is State.OPEN:
            self._opened_at = self.clock()

    @contextmanager
    def attempt(self) -> Iterator[None]:
        self.check()
        if self.state is State.OPEN:
            self._transition(State.HALF_OPEN)
        probe = self.state is State.HALF_OPEN
        generation = self._generation
        if probe:
            self._inflight += 1
        try:
            yield
        except TransientFailure:
            if generation == self._generation:
                self._failures += 1
                if probe or self._failures >= self.settings.failure_threshold:
                    self._transition(State.OPEN)
            raise
        else:
            if generation == self._generation:
                self._failures = 0
                if probe:
                    self._successes += 1
                    if self._successes == self.settings.probes:
                        self._transition(State.CLOSED)
        finally:
            if probe and generation == self._generation:
                self._inflight -= 1
