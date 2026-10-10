#!/usr/bin/env bash
# Unattended AI agent runs.
claude -p "fix lint errors" --dangerously-skip-permissions  # expect[AGT014]
codex exec --dangerously-bypass-approvals-and-sandbox "upgrade deps"  # expect[AGT014]
gemini --yolo -p "clean up the repo"  # expect[AGT014]
claude -p "summarise the diff" --allowedTools "Read"  # safe[AGT014]
echo "Reminder: never use --yolo in CI"  # noisy[AGT014] a warning message, not a flag
