"""
Guard: turn a policy Decision into an outcome, run allowed commands, and write
an append-only audit log (JSON Lines) of everything that was proposed.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .policy import Decision, Policy


@dataclass
class Outcome:
    command: str
    action: str          # allow | deny | confirm
    reason: str
    executed: bool
    returncode: int | None
    timestamp: str


def audit(path: str | Path, outcome: Outcome) -> None:
    """Append one JSON record. Append-only: we never rewrite existing lines."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(outcome)) + "\n")


def read_audit(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.is_file():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def evaluate(command: str, policy: Policy) -> Decision:
    return policy.decide(command)


def guard(command: str, policy: Policy, *, audit_path: str | Path | None = None,
          approve_confirms: bool = False, dry_run: bool = False,
          cwd: str | Path = ".") -> Outcome:
    """
    Decide on `command`, optionally run it, and record the outcome.

    - allow   -> run (unless dry_run)
    - deny    -> never run
    - confirm -> run only if approve_confirms (the CLI sets this after a yes/no
                 prompt); otherwise treated as blocked here.
    """
    decision = policy.decide(command)
    should_run = (decision.action == "allow"
                  or (decision.action == "confirm" and approve_confirms))
    executed, rc = False, None
    if should_run and not dry_run:
        proc = subprocess.run(["bash", "-c", command], cwd=str(cwd))
        executed, rc = True, proc.returncode

    outcome = Outcome(command=command, action=decision.action, reason=decision.reason,
                      executed=executed, returncode=rc, timestamp=_now())
    if audit_path:
        audit(audit_path, outcome)
    return outcome
