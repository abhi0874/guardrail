from mcp_agent_server.storage.connection import Connection
from mcp_agent_server.tools.models import NoteReceipt


def insert_note(db: Connection, title: str, body: str) -> NoteReceipt:
    row = db.execute(
        "INSERT INTO notes(title,body) VALUES (?,?) RETURNING note_id", (title, body)
    ).fetchone()
    return NoteReceipt(note_id=row[0])
