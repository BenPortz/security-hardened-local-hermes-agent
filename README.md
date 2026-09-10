# security-hardened-local-hermes-agent

An autonomous agent platform that runs entirely on a dedicated local machine. It is built to
take sensitive or repetitive tasks off a main work machine without sending their content to a
cloud provider, and to run the kind of bulk work that would otherwise be metered against an
API bill.

The agent works through a queue of projects one step at a time. When it reaches a decision it
cannot make on its own, it asks a question, parks that project, and moves to the next one. You
answer from your phone and it picks the project back up.

Most of the work in this repo is in the containment around the agent. The design assumes the
agent can be manipulated by the content it reads, and is arranged so that this has limited
effect.

```
  Dedicated agent host (16GB Apple Silicon, encrypted, egress-locked)
  |-- local inference server --serves--> mid-size quantized model   <- the brain, on-device
  |-- agent harness --talks to--> http://127.0.0.1:11434/v1         <- LOCAL endpoint only
  |     |-- skills / cross-session memory
  |     +-- minimal toolsets per task (structural capability limits)
  |-- Orchestration: project queue - clarification loop - async scheduler
  |-- Ingestion:     out-of-band read-only mail fetch -> inert local records
  |-- Security:      default-deny egress - least-priv creds - structural approval gates
  +-- Monitoring:    Tier A log -> Tier B alerts -> Tier C digest -> Tier D roll-up

  Private mesh (WireGuard) --> phone dashboard + self-hosted push
                               the approval surface, from anywhere
```

## Why this exists

There are two reasons, and they happen to want the same system.

The first is cost. Repetitive or bulk work, such as triaging a mailbox, summarizing a backlog
or producing first drafts, spends frontier-model tokens on tasks a 14B-class local model can
handle. Running those locally costs electricity instead. Frontier models remain available as a
per-question escalation.

The second is privacy. The tasks most worth automating tend to involve content you would
rather not hand to a third party. Running the model locally covers half of that. The other
half is making sure the agent itself cannot send the data out, which is what most of the
design below is about.

## Threat model

The agent should be treated as untrusted from the moment it reads an email.

The realistic attack is indirect prompt injection: text inside a document or message persuades
the agent to misuse the access it legitimately has: sending, deleting, leaking, or writing
itself a new capability. Nothing appears on the machine that a scanner would flag, because the
agent is acting normally with valid credentials.

Two things follow from that, and they shape most of the decisions in this repo:

1. The model cannot be the gate. A model that can be talked into taking an action can also be
   talked into reporting that it did not. Gates need to be structural, enforced by code the
   agent does not call, using credentials the agent does not hold.
2. Detection does not undo a leak. So most of the effort goes into preventive controls (egress
   lock, least-privilege credentials, capability limits) and the rest into detective ones (the
   monitoring tiers). Preventive controls get built first.

See [docs/security-model.md](docs/security-model.md).

## How containment works

| Control | What it buys |
|---|---|
| **Default-deny egress firewall** | A compromised agent has nowhere to send anything. The single most useful control. |
| **Out-of-band ingestion** | A trusted non-agent process fetches mail read-only into inert local files. The agent never holds the mail credential and never makes a network call. |
| **Minimal toolsets per task** | Triage runs with a memory-only toolset: no network tool, no send tool. An injection that persuades the model still has nothing available to act with. |
| **Structural approval gates** | The agent produces a draft; a separate human-approved path performs the send. Enforced outside the agent, since headless runs bypass harness prompts. |
| **Least-privilege credentials** | A read-only OAuth scope, re-checked by the fetcher at startup, which exits if the token carries anything broader. |
| **Deterministic audit** | Every action is appended to JSONL and compared against allowlists. Comparison is mechanical; a model may reformat a digest for reading. |

## Repo layout

```
docs/
  architecture.md      the design, and the reasoning behind each decision
  security-model.md    threat model and the control list
  monitoring-tiers.md  the A/B/C/D audit design
  orchestrator.md      project state machine and async scheduling
  email-ingestion.md   the out-of-band read-only mail pipeline
  deployment.md        standing the host up, in order, with the firewall last
scripts/
  audit_logger.py      Tier A - append-only JSONL + new-vs-known classification
  alert.py             Tier B - real-time push for high-blast-radius events
  workflow_digest.py   Tier C - per-workflow summary
  nightly_rollup.py    Tier D - trends and anomalies
  daily_digest.py      morning health push that doubles as a liveness check
  hub.py               mesh-only API + mobile dashboard (stdlib, no framework)
  gmail_auth.py        one-time read-only OAuth mint (loopback + PKCE, stdlib)
  gmail_fetch.py       read-only fetcher -> inert inbox records
  draft_reply.py       local model drafts a reply; never sends
  orchestrator/
    scheduler.py       single-flight loop: pick, step, persist, repeat
    cloud_ask.py       optional per-question cloud escalation
config/                templates only - no real configuration is committed
allowlists/            known hosts / skills / credential-uses
inbox/  projects/      record schemas and examples
```

## Implementation notes

**Stdlib only.** The hub, the dashboard, the OAuth flow, the mail client and the scheduler use
no third-party packages. On a host with locked-down egress you cannot install anything
casually, and each dependency is another thing that can make network calls. The Gmail API is
plain REST and JSON, so token refresh, list and get are a handful of `urllib` calls.

**Every model-output contract has a deterministic backstop.** Small local models drift from
formatting instructions: they bullet required markers, wrap fields across lines, and re-ask
questions that were already answered. The parsers have layered fallbacks, and a counter ends a
runaway clarification loop.

**Restricting toolsets serves two purposes.** It is the security control, and it is also the
main performance lever: the full tool-schema block is tens of kilobytes reprocessed on every
agentic turn, which dominates step latency on a laptop-class host.

**Mode switching does not require a redeploy.** `config/mode.env` decides whether the
scheduler drives the queue or idles, and it is read each loop iteration.

**Escalation degrades gracefully.** A cloud ask falls back through claude → chatgpt → local
model, and the answer carries a note of what failed along the way, so a plan limit or a missing
CLI still produces an answer.

**A missing signal is the alarm.** The daily digest runs on a schedule, so its absence is what
indicates a problem. A host that has stopped working cannot report that itself.

## Status

This is a personal reference implementation, published as a portfolio piece. The code is the
real implementation and the docs describe the design and the reasoning behind it. Standing it
up means following [docs/deployment.md](docs/deployment.md) on a host you control, and the
security properties depend on the host-level controls described there being in place.

Built on the [Hermes Agent](https://github.com/NousResearch/hermes-agent) harness and an
OpenAI-compatible local inference server. Both are replaceable: the harness is invoked as a
subprocess behind one constant, and the model endpoint is one line of config.
