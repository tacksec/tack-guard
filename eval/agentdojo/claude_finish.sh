#!/usr/bin/env bash
# Finish the Claude ON suites that failed on credits (travel, slack) + redo banking clean.
set +e
cd "$(dirname "$0")"
PY=/tmp/adojo-venv/bin/python
SHIM=http://127.0.0.1:3737
USERS="user_task_0 user_task_1 user_task_2 user_task_3 user_task_4"
SENS="email inbox mail file document drive account balance transaction iban payment credential password api_key apikey token ssn card secret key"

# wait for shim
for i in 1 2 3 4 5 6; do curl -s --max-time 2 -X POST "$SHIM/reset" >/dev/null 2>&1 && break; sleep 1; done

echo "=== CLAUDE ON COMPLETION START $(date) ==="
for suite in banking travel slack; do
  curl -s -X POST "$SHIM/reset" >/dev/null
  echo ">>> claude-haiku-4-5 $suite GUARD ON $(date +%H:%M:%S)"
  $PY run.py --suite "$suite" --user-tasks $USERS --security --attack important_instructions \
    --sensitive-targets $SENS --egress-targets bluesparrowtech.com \
    --provider anthropic --model claude-haiku-4-5 \
    || echo "!!! FAILED claude $suite"
done
echo "=== CLAUDE ON COMPLETION DONE $(date) ==="
