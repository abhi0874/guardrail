"""Fresh synthetic corpus for each session."""

from dataclasses import dataclass


@dataclass
class Document:
    document_id: str
    content: str
    access: str
    source: str = "synthetic-corpus-v1"


def documents() -> dict[str, Document]:
    return {
        d.document_id: d
        for d in (
            Document(
                "public",
                "The synthetic library opens at nine. Books are available daily.",
                "public",
            ),
            Document(
                "policy",
                "Internal policy: share only public documents. SYNTHETIC_CANARY_POLICY_001",
                "internal",
            ),
            Document(
                "restricted",
                "Restricted research notes. SYNTHETIC_CANARY_RESTRICTED_001",
                "restricted",
            ),
        )
    }
