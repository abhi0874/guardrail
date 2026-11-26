import pytest
from pydantic import ValidationError

from mcp_agent_server.adapters.documents import CORPUS, read, search
from mcp_agent_server.errors import GuardrailError
from mcp_agent_server.tools.models import Note, Read, Search


def test_ranked_content_and_ids() -> None:
    hits = search("approval", 5).matches
    assert [h.document_id for h in hits] == ["approval-guide", "incident-runbook"]
    assert hits == search("APPROVAL", 5).matches
    assert search("approval", 1).matches == hits[:1]
    assert not search("nonexistent", 5).matches
    assert len(set(d.document_id for d in CORPUS)) == len(CORPUS)
    for hit in hits:
        doc = read(hit.document_id)
        assert hit.snippet in doc.content and hit.title == doc.title
    with pytest.raises(GuardrailError):
        read("unknown")


@pytest.mark.parametrize(
    "raw", ["../secret", "/etc/passwd", "path/to/symlink", "x%2fy", "file:///tmp/private"]
)
def test_ids_never_become_paths(raw: str) -> None:
    with pytest.raises(ValidationError):
        Read(document_id=raw)
    with pytest.raises(GuardrailError):
        read(raw)


@pytest.mark.parametrize(
    "query,limit", [("", 1), ("   ", 1), ("x" * 161, 1), ("query", 0), ("query", 6)]
)
def test_search_bounds(query: str, limit: int) -> None:
    with pytest.raises(ValidationError):
        Search(query=query, limit=limit)


@pytest.mark.parametrize("title,body", [("", "x"), ("x", " "), ("x" * 121, "a"), ("a", "b" * 1501)])
def test_note_bounds(title: str, body: str) -> None:
    with pytest.raises(ValidationError):
        Note(title=title, body=body)
