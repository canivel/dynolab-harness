#!/usr/bin/env bash
# Step 2: serve one open-weight model with tool calling on 127.0.0.1:8000.
# Take TOOL_PARSER from the model card or vLLM's tool-calling docs. For
# gpt-oss-20b it is "openai"; for Qwen3 models it is usually "hermes".
set -euo pipefail
MODEL_ID="${MODEL_ID:-openai/gpt-oss-20b}"
TOOL_PARSER="${TOOL_PARSER:?set TOOL_PARSER for this model}"
REVISION="${REVISION:-main}"   # pin to a commit hash and copy it into harness.yaml

exec vllm serve "$MODEL_ID" --revision "$REVISION" \
  --host 127.0.0.1 --port 8000 \
  --max-model-len 32768 \
  --enable-auto-tool-choice --tool-call-parser "$TOOL_PARSER"
