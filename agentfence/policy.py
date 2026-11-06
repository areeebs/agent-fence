"""
Policy engine for agent-fence.

A policy is JSON: an ordered list of rules, each a regex `pattern` and an
`action` (allow | deny | confirm), plus a `default_action` for commands that
match nothing. Rules are evaluated in order; the first match wins. This makes
the policy auditable and easy to reason about — no hidden scoring.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ACTIONS = {"allow", "deny", "confirm"}


@dataclass
class Rule:
    action: str
    pattern: str
    note: str = ""

    def __post_init__(self):
        if self.action not in ACTIONS:
            raise ValueError(f"invalid action '{self.action}'; use one of {sorted(ACTIONS)}")
        self._rx = re.compile(self.pattern, re.I)

    def matches(self, command: str) -> bool:
        return bool(self._rx.search(command))


@dataclass
class Decision:
    action: str          # allow | deny | confirm
    reason: str          # which rule, or "default"
    pattern: str | None


class Policy:
    def __init__(self, rules: list[Rule], default_action: str = "confirm") -> None:
        if default_action not in ACTIONS:
            raise ValueError(f"invalid default_action '{default_action}'")
        self.rules = rules
        self.default_action = default_action

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        rules = [Rule(**r) for r in data.get("rules", [])]
        return cls(rules, data.get("default_action", "confirm"))

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def decide(self, command: str) -> Decision:
        for rule in self.rules:
            if rule.matches(command):
                note = f": {rule.note}" if rule.note else ""
                return Decision(rule.action, f"matched /{rule.pattern}/{note}", rule.pattern)
        return Decision(self.default_action, "default (no rule matched)", None)


def default_policy() -> Policy:
    """A conservative starter policy used when the user supplies none."""
    return Policy.from_dict({
        "default_action": "confirm",
        "rules": [
            {"action": "deny", "pattern": r"rm\s+-rf\s+[/~]", "note": "recursive delete of / or home"},
            {"action": "deny", "pattern": r":\(\)\s*\{\s*:\|:&\s*\}", "note": "fork bomb"},
            {"action": "deny", "pattern": r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(sh|bash)", "note": "pipe-to-shell"},
            {"action": "deny", "pattern": r"chmod\s+-R?\s*777", "note": "world-writable"},
            {"action": "deny", "pattern": r">\s*~?/?\.ssh/|~/\.aws/credentials", "note": "writes to credentials"},
            {"action": "confirm", "pattern": r"\bsudo\b", "note": "privilege escalation"},
            {"action": "confirm", "pattern": r"\b(curl|wget|scp|ssh|nc)\b", "note": "network access"},
            {"action": "confirm", "pattern": r"\bgit\s+push\b", "note": "publishes code"},
            {"action": "allow", "pattern": r"^\s*(ls|pwd|cat|echo|head|tail|grep|find|git\s+(status|log|diff|branch)|python3?\s+-m\s+pytest|npm\s+test)\b"},
        ],
    })
