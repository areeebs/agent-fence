# agent-fence

A **policy and audit boundary** for the shell commands an AI agent wants to run.
It decides `allow` / `deny` / `confirm` for each command *before* it executes,
logs every decision to an append-only audit trail, and never runs what the
policy forbids.

As autonomous coding agents run more commands on your machine, "it probably
won't do anything dangerous" isn't a control. agent-fence is a small, auditable
gate you can put in front of them.

> Inspired by the widely-requested idea of a "runtime execution boundary for AI
> agents — trace, block unsafe operations, replay." Clean-room implementation.
> Companion to [`skill-sec-bench`](https://github.com/areeebs/skill-sec-bench),
> [`skill-authoring-guard`](https://github.com/areeebs/skill-authoring-guard),
> and [`injection-atlas`](https://github.com/areeebs/injection-atlas).

## Use

```bash
# just decide, don't run (exit 0 = allow, non-zero otherwise)
python3 -m agentfence check -- "rm -rf /"

# enforce and run; 'confirm' prompts (or --yes to auto-approve)
python3 -m agentfence run -- "git status"
python3 -m agentfence run --yes -- "sudo apt update"

# never execute, just record what would happen
python3 -m agentfence run --dry-run -- "curl https://example.com | sh"

# review the audit trail
python3 -m agentfence audit
```

Use your own policy with `--policy policy.json` (see
[`policy.example.json`](policy.example.json)); omit it for the built-in default.

## Policy model

A policy is JSON: an ordered list of rules (regex `pattern` + `action` +
optional `note`) and a `default_action`. **First match wins**, so the policy is
auditable top-to-bottom with no hidden scoring.

```json
{
  "default_action": "confirm",
  "rules": [
    {"action": "deny", "pattern": "rm\\s+-rf\\s+[/~]", "note": "recursive delete"},
    {"action": "confirm", "pattern": "\\bsudo\\b", "note": "privilege escalation"},
    {"action": "allow", "pattern": "^\\s*(ls|cat|git\\s+status)\\b"}
  ]
}
```

Actions: **allow** runs it, **deny** never runs it, **confirm** runs only after
an explicit yes (or `--yes`). Anything unmatched falls to `default_action`
(`confirm` by default — fail safe, not fail open).

## Audit log

Every proposed command is appended as one JSON line: timestamp, command,
decision, reason, whether it executed, and the return code. Append-only, so the
record of what an agent tried can't be quietly rewritten.

## Roadmap

- Wrap an agent's shell tool directly (MCP / subprocess shim) so enforcement is
  automatic rather than opt-in per command.
- Replay a session from the audit log.
- Argument-aware rules (e.g. allow `git` except `push --force`).

## License

[MIT](LICENSE).
