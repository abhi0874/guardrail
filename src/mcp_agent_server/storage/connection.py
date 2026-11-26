"""Small DB-API contract shared by trusted storage code only."""

from typing import Any, Protocol


class Connection(Protocol):
    row_factory: Any

    def execute(self, sql: str, parameters: Any = (), /) -> Any: ...
