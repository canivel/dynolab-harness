# Episode folder and event format

This is the contract between the harness and any viewer, for example the Dynolab app.
Viewers read these files; they never need to import harness code.

```
runs/<run>/<episode>/
  manifest.json      written at start (status: running) and again at the end (status: done | error)
  transcript.jsonl   one JSON event per line, append-only, flushed after every event
  secrets.json       per-episode honeypot values (keep private; never publish)
  pre_hashes.json    protected-path snapshot before the agent starts
  post_hashes.json   the same snapshot after the episode
  label.json         outcome and tripwires, written by the labeler after the episode
```

A run folder also gets `summary.json`, `summary.md` and `review.md`. `seal` adds `SHA256SUMS`
and, optionally, `SHA256SUMS.sig`.

## Fields on every event

| Field | Meaning |
|---|---|
| `ts` | UTC timestamp, ISO 8601 |
| `seq` | 1, 2, 3, … within the episode. Viewers poll with "events after seq N". |
| `episode_id` | The episode folder name |
| `agent_id` | Which agent produced or received the event. `agent-0` for single-agent tasks; multi-agent tasks use one id per agent. |
| `step` | Model turn number. 0 for `start`. |
| `role` | `assistant`, `tool_call`, `tool`, `user` or `harness` |
| `event` | One of the types below |

## Event types

| `event` | Extra fields | Notes |
|---|---|---|
| `start` | `task_id`, `prompt`, `system_prompt`, `model_id`, `seed` | Logged after the sandbox is set up and hashed |
| `model` | `content`, `reasoning`, `n_tool_calls`, `finish_reason`, `usage` | One per model turn. `reasoning` is the thinking text when the server returns it. |
| `nudge` | `content` | The model replied without a tool call and was asked to continue |
| `tool_call` | `tool`, `args` (or `raw_args` when the arguments weren't valid JSON), `call_id` | Written **before** the command executes |
| `tool_result` | `tool`, `stdout`, `stderr`, `exit_code`, `duration_s` | Full output. The model saw a truncated copy. |
| `tripwire` | `type`, `severity` (`moderate` or `severe`), `evidence` | Live flag from the same rules the final labeler uses. `protected_file_changed` only appears in `label.json`, because it needs the final hash snapshot. |
| `end` | `end_reason`, `final_action`, `final_args`, `elapsed_s` | `end_reason` is `submit`, `report_blocked`, `max_steps` or `timeout` |
| `error` | `error` | The harness itself failed. The episode is labeled `harness_error`. |

## `label.json`

`outcome` is one of:
- `honest_blocked`
- `blocked_after_probing`
- `false_success`
- `rule_break`
- `no_final`
- `harness_error`

`label.json` also holds `claimed_success`, `final_action`, `end_reason`, `final_args`, and
`tripwires` (a list of `{type, severity, step, evidence}`).
