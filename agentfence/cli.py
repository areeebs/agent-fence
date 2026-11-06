#!/usr/bin/env python3
"""
agent-fence - a policy + audit boundary for commands an AI agent wants to run.

  python3 -m agentfence check  -- <command...>            # decide only, don't run
  python3 -m agentfence run     [--yes] -- <command...>    # enforce + run + log
  python3 -m agentfence audit                              # show the audit log

Options: --policy FILE (JSON; omit for the built-in default), --audit FILE,
--dry-run (never execute), --cwd DIR.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from .policy import Policy, default_policy
    from .guard import guard, read_audit
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from agentfence.policy import Policy, default_policy
    from agentfence.guard import guard, read_audit


def _load_policy(path):
    return Policy.load(path) if path else default_policy()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Everything after the first "--" is the command; parse only the head as
    # flags. (Avoids argparse.REMAINDER swallowing our own options.)
    if "--" in argv:
        i = argv.index("--")
        head, command = argv[:i], " ".join(argv[i + 1:]).strip()
    else:
        head, command = argv, ""

    ap = argparse.ArgumentParser(prog="agentfence", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["check", "run", "audit"])
    ap.add_argument("--policy")
    ap.add_argument("--audit", default="agentfence.audit.jsonl")
    ap.add_argument("--yes", action="store_true", help="auto-approve 'confirm' decisions")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--cwd", default=".")
    args = ap.parse_args(head)

    if args.cmd == "audit":
        rows = read_audit(args.audit)
        if not rows:
            print("(audit log empty)")
        for r in rows:
            run = "ran" if r["executed"] else "blocked"
            print(f"{r['timestamp']}  {r['action']:7} {run:7} rc={r['returncode']}  {r['command']}")
        return 0

    policy = _load_policy(args.policy)
    if not command:
        print("error: no command given (use: ... -- <command>)", file=sys.stderr)
        return 2

    decision = policy.decide(command)

    if args.cmd == "check":
        print(f"{decision.action.upper()}: {command}\n  reason: {decision.reason}")
        return 0 if decision.action == "allow" else 1

    # run
    approve = args.yes
    if decision.action == "confirm" and not args.yes:
        if sys.stdin.isatty():
            approve = input(f"CONFIRM: run `{command}`? [y/N] ").strip().lower() in ("y", "yes")
        else:
            print(f"CONFIRM needed for `{command}` but no TTY; pass --yes to approve. Blocked.",
                  file=sys.stderr)
    if decision.action == "deny":
        print(f"DENIED: {command}\n  reason: {decision.reason}", file=sys.stderr)

    outcome = guard(command, policy, audit_path=args.audit,
                    approve_confirms=approve, dry_run=args.dry_run, cwd=args.cwd)
    status = "ran" if outcome.executed else "blocked"
    print(f"[{outcome.action}] {status}: {command}"
          + (f" (rc={outcome.returncode})" if outcome.executed else ""))
    if outcome.executed:
        return outcome.returncode or 0
    return 0 if outcome.action == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
