#!/usr/bin/env bash
# Re-run ONLY the guard-ON steps with the per-episode isolation fix.
# OFF steps from the first sweep stay valid (no guard = no state to contaminate).
set +e
cd "$(dirname "$0")"
PY=/tmp/adojo-venv/bin/python
SHIM=http://127.0.0.1:3737
ATTACK=important_instructions
USERS="user_task_0 user_task_1 user_task_2 user_task_3 user_task_4"
SENS="email inbox mail file document drive account balance transaction iban payment credential password api_key apikey token ssn card secret key"
EGRESS="bluesparrowtech.com"
SUITES="workspace banking travel slack"

echo "=== ON RE-RUN START $(date) ==="
for ms in "openai gpt-4o-mini" "anthropic claude-haiku-4-5"; do
  set -- $ms; provider=$1; model=$2
  for suite in $SUITES; do
    curl -s -X POST "$SHIM/reset" >/dev/null
    echo ">>> [$provider:$model] $suite  GUARD ON  $(date +%H:%M:%S)"
    $PY run.py --suite "$suite" --user-tasks $USERS --security --attack "$ATTACK" \
      --sensitive-targets $SENS --egress-targets $EGRESS \
      --provider "$provider" --model "$model" \
      || echo "!!! FAILED ON $provider:$model $suite"
  done
done
echo "=== ON RE-RUN DONE $(date) ==="
