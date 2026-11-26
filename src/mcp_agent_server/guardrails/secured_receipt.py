from dataclasses import dataclass

from mcp_agent_server.idempotency.models import ReceiptCodec

from .output_filtering import OutputGuard, Render


@dataclass(frozen=True)
class SecuredReceipt:
    """Guard both storage ingress (including local SQL effects) and historical cache egress."""

    base: ReceiptCodec
    guard: OutputGuard
    tool: str
    render: Render | None

    @property
    def total_seconds(self) -> float:
        return self.base.total_seconds

    def encode(self, data: object) -> str:
        encoded = self.base.encode(data)
        clean = self.guard.receipt(encoded, self.tool)
        return self.base.encode(clean)

    def response(self, receipt: str, replay: bool) -> dict[str, object]:
        original = self.base.response(receipt, replay)
        safe = self.encode(original["structuredContent"])
        projected = self.base.response(safe, replay)
        if self.render is None:
            return projected
        return self.render(self.tool, projected["structuredContent"], replay)
