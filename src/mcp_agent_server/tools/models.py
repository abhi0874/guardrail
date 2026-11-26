from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")


Query = Annotated[str, StringConstraints(min_length=1, max_length=160, pattern=r"\S")]
Limit = Annotated[int, Field(ge=1, le=5)]
DocumentId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,47}$")]


def safe_text(value: str) -> str:
    if any(ord(c) < 32 and c not in "\n\r\t" for c in value):
        raise ValueError("Invalid control character")
    return value


Title = Annotated[
    str, StringConstraints(min_length=1, max_length=120, pattern=r"\S"), AfterValidator(safe_text)
]
Body = Annotated[
    str, StringConstraints(min_length=1, max_length=1500, pattern=r"\S"), AfterValidator(safe_text)
]
Recipient = Literal["ops-lab", "docs-lab"]
UrlText = Annotated[str, StringConstraints(min_length=1, max_length=2048)]


class Health(Contract):
    status: Literal["ok"] = "ok"
    service: str
    version: str


class Search(Contract):
    query: Query
    limit: Limit = 3


class Read(Contract):
    document_id: DocumentId


class Note(Contract):
    title: Title
    body: Body


class Message(Contract):
    recipient: Recipient
    subject: Title
    body: Body


class Fetch(Contract):
    url: UrlText


class Metadata(Contract):
    document_id: DocumentId
    title: Title
    category: str


class Document(Metadata):
    content: Annotated[str, Field(min_length=1, max_length=8192)]


class Hit(Metadata):
    snippet: Annotated[str, Field(max_length=180)]


class Matches(Contract):
    matches: list[Hit] = Field(max_length=5)


class NoteReceipt(Contract):
    note_id: int = Field(gt=0)
    persisted: Literal[True] = True


class MessageReceipt(Contract):
    simulation_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    recipient: Recipient
    recorded_in_memory: Literal[True] = True


class Page(Contract):
    host: str
    media_type: Literal["text/plain", "text/markdown"]
    text: Annotated[str, Field(max_length=16384)]
