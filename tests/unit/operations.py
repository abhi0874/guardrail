import json

from pydantic import BaseModel, ConfigDict

from mcp_agent_server.guardrails.policy import Policy, parse_policy


class Args(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    recipient: str
    number: int
    category: str
    approved: bool = False


def snapshot(
    *,
    action: str = "permit",
    roles: tuple[str, ...] = (),
    principal: str = "local-anonymous",
    approval: bool = True,
) -> Policy:
    rule = {
        "action": action,
        "approval_required": approval,
        "principals": [principal],
        "roles": roles,
        "constraints": [
            {"op": "equals", "field": "recipient", "value": "inbox"},
            {"op": "one_of", "field": "category", "values": ["a", "b"]},
            {"op": "integer_range", "field": "number", "minimum": 1, "maximum": 4},
        ],
    }
    return parse_policy(
        json.dumps(
            {
                "schema_version": "1",
                "default_action": "deny",
                "rules": [dict(rule, tool="write"), dict(rule, tool="copy")],
            }
        ).encode()
    )
