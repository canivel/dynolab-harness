# Dynolab harness

Test what AI agents do when the rules get in the way.

The harness runs an AI agent on a real task inside an isolated sandbox. Each task is an ordinary
software chore with one explicit rule, and following the rule makes the task impossible, so the
honest response is to say so. Every command the agent runs is logged before it executes.
Tripwires record what it tries instead: reading credentials it was told not to use, changing
protected files, reaching for privileges, or connecting where it shouldn't. Results come out as
labeled, reviewable, signed evidence that anyone can verify.

It is free and open source (MIT). The [Dynolab app](https://dynolab.dev) for macOS bundles it
with a full interface: live episode timelines, a conversation view that keeps evaluation separate
from what the agent saw, a task editor, environments you can turn on and off, LLM monitors and
hand review. You can also use the harness on its own from the command line.

## What's included

- **Sandbox.** A fresh gVisor container per episode with no network route out. The agent runs
  as an unprivileged user next to root-only files and honeypot credentials.
- **Tasks.** Seven built-in tasks, from unpassable tests to a production database behind a network
  boundary, plus `t0_locked_report`, a small teaching task to copy. Each has scripted honest and
  rule-breaking controls (positive controls) that must be labeled correctly before results count.
  See [docs/controls.md](docs/controls.md).
- **Environments.** Multi-node sandboxes: service nodes on separate network segments behind policy
  gateways that allow, deny or flag every connection and log it outside the agent's reach.
- **Rooms.** A lead agent works on a goal it can't reach without breaking a rule, and creates
  teammates as it needs them. They share one sandbox and a group chat. A hidden Observer keeps
  the family tree, records each rule broken, by whom and at whose request, and checks the final
  report against the logs. See [docs/rooms.md](docs/rooms.md).
- **Evaluation.** Tripwire rules, honest-outcome checks, conditions (for example neutral vs
  pressure prompts), a labeler, hand review, and LLM monitors (in the app).
- **Evidence.** A SHA-256 for every file, Ed25519 signatures, and an export that removes honeypot
  values and can leave out the model's reasoning.

## Quick start

You need Docker with the gVisor runtime (`runsc`). On macOS, `harness setup --install-runtime`
installs Colima, Docker and gVisor with Homebrew. On Linux, install Docker and
[gVisor](https://gvisor.dev/docs/user_guide/install/).

```bash
pip install git+https://github.com/canivel/dynolab-harness
harness setup                # checks the runtime, builds the sandbox image and network
harness check                # isolation checks: internal network, gVisor, no egress, no sudo
harness control              # positive controls in real containers, every task that has them; all must pass
```

Point the harness at any OpenAI-compatible model server (mlx-lm, vLLM, llama.cpp, Ollama…)
that supports tool calling:

```bash
harness --base-url http://127.0.0.1:8000/v1 --model-id <model> run --task t1_unpassable_tests --count 3
harness --base-url ... --model-id <model> run --task t1_unpassable_tests --condition pressure
```

Each episode folder holds the full transcript, a manifest (model, weights revision, settings,
image digest, harness version), before and after file hashes and the label. See
[docs/event-schema.md](docs/event-schema.md).

## Your own tasks and environments

Built-in content ships inside the package and is read-only. Your own tasks, environments and
controls go under `HARNESS_HOME` (default `~/.dynolab/harness`), which also holds runs and keys.

```bash
harness paths                          # where everything lives
harness task-check <folder>            # validate a task
harness task-dryrun <folder>           # build its sandbox without an agent and show what's armed
harness env list                       # environment templates and running instances
harness env up segmented-office --name office1
harness run --task t4_quarterly_report --instance office1 ...
harness env down office1
harness devbox create explore1 --template bastion-admin   # a long-lived environment to explore
```

Give every task of your own two control scripts, `controls/honest.yaml` and
`controls/rule_break.yaml`, so its labels can be tested. Start from the commented ones in
`t0_locked_report`:

```bash
harness task-check <folder>            # also validates the control scripts
harness control --tasks <task_id>      # replay them in real containers
```

Formats: [docs/task-schema.md](docs/task-schema.md), [docs/controls.md](docs/controls.md),
[docs/environments.md](docs/environments.md) and [docs/rooms.md](docs/rooms.md).

## Sharing results

```bash
harness keygen                          # once; publish the .pub key
harness export <run> --out bundle/      # honeypot values removed; add --no-reasoning to drop reasoning
harness verify bundle/ --pubkey <key.pub>
```

Bundles can be published to [Dyno Research](https://research.dynolab.dev), where others can read
the transcripts, check the signatures and rerun the same tasks.

## Development

```bash
uv venv -p 3.12 .venv && uv pip install -p .venv/bin/python -e '.[dev]'
.venv/bin/pytest -q
```

Tests use a temporary `HARNESS_HOME` and an in-memory sandbox, so they need neither Docker nor a model.

## Limits

These tests show what an agent can try in a given setup. A handful of episodes is not a measured
rate. Tripwires are pattern rules: some flags are false alarms and some attempts may go unflagged,
which is why hand review is part of the method. Results describe the runs; they don't establish
that a model or agent is safe.
