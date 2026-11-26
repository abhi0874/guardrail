"""Validated in-memory tools. No network, filesystem or real identity changes."""

import re

from agent_security_scanner.contracts import JSONObject, JSONValue
from agent_security_scanner.sandbox.documents import documents


class ToolError(ValueError):
    """Invalid or unauthorized synthetic action."""


class Tools:
    def __init__(self, role: str = "reader") -> None:
        if role not in {"reader", "staff", "admin"}:
            raise ToolError("Unknown synthetic role")
        self.role = role
        self.documents = documents()
        self.outbox: list[JSONObject] = []

    def visible(self, access: str) -> bool:
        return (
            access == "public"
            or self.role == "admin"
            or (self.role == "staff" and access == "internal")
        )

    def execute(self, name: str, args: JSONObject) -> JSONValue:
        schemas = {
            "search_documents": {"query"},
            "read_document": {"document_id"},
            "send_message": {"recipient", "message"},
            "update_document": {"document_id", "content"},
            "change_access_level": {"document_id", "access"},
        }
        if name not in schemas or set(args) != schemas[name]:
            raise ToolError("Unknown tool or invalid argument names")
        if any(not isinstance(v, str) or not v.strip() or len(v) > 10000 for v in args.values()):
            raise ToolError("Arguments must be nonempty strings of at most 10000 characters")
        # Validated strings are copied to a narrowly typed mapping.
        values = {k: v for k, v in args.items() if isinstance(v, str)}
        if name == "search_documents":
            terms = set(re.findall(r"\w+", values["query"].lower()))
            ranked = sorted(
                (
                    (len(terms & set(re.findall(r"\w+", d.content.lower()))), d.document_id)
                    for d in self.documents.values()
                    if self.visible(d.access)
                ),
                key=lambda item: (-item[0], item[1]),
            )
            return [identifier for score, identifier in ranked if score > 0]
        if name == "send_message":
            if values["recipient"] not in {"synthetic-inbox"}:
                raise ToolError("Only synthetic-inbox is permitted")
            message: JSONObject = {"recipient": values["recipient"], "message": values["message"]}
            self.outbox.append(message)
            return {"stored_message_index": len(self.outbox) - 1}
        document = self.documents.get(values["document_id"])
        if document is None or not self.visible(document.access):
            raise ToolError("Document unavailable for this role")
        if name == "read_document":
            return {
                "document_id": document.document_id,
                "content": document.content,
                "access": document.access,
                "source": document.source,
            }
        if self.role != "admin":
            raise ToolError("Only synthetic admin may modify documents")
        if name == "update_document":
            document.content = values["content"]
        else:
            if values["access"] not in {"public", "internal", "restricted"}:
                raise ToolError("Invalid access level")
            document.access = values["access"]
        return {
            "document_id": document.document_id,
            "access": document.access,
            "content": document.content,
        }
