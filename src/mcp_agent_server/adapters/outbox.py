from uuid import uuid4

from mcp_agent_server.tools.models import Message, MessageReceipt


class Outbox:
    """One server process. Receipts attest to a historical append only."""

    def __init__(self) -> None:
        self.entries: list[tuple[MessageReceipt, Message]] = []

    def record(self, message: Message) -> MessageReceipt:
        receipt = MessageReceipt(simulation_id=uuid4().hex, recipient=message.recipient)
        self.entries.append((receipt, message))
        return receipt
