#!/usr/bin/env bash
# Breadth sweep: all injection tasks x 5 user tasks, 4 suites, 2 models, guard OFF+ON.
# Direct OpenAI + Anthropic APIs (keys from ../../.env.local). Costs logged to runs/costs.jsonl.
set +e
cd "$(dirname "$0")"
PY=/tmp/adojo-venv/bin/python
SHIM=http://127.0.0.1:3737
ATTACK=important_instructions
USERS="user_task_0 user_task_1 user_task_2 user_task_3 user_task_4"
SENS="email inbox mail file document drive account balance transaction iban payment credential password api_key apikey token ssn card secret key"
EGRESS="bluesparrowtech.com"
SUITES="workspace banking travel slack"

echo "=== BREADTH SWEEP START $(date) ==="
for ms in "openai gpt-4o-mini" "anthropic claude-haiku-4-5"; do
  set -- $ms; provider=$1; model=$2
  for suite in $SUITES; do
    echo ">>> [$provider:$model] $suite  GUARD OFF  $(date +%H:%M:%S)"
    $PY run.py --suite "$suite" --user-tasks $USERS --security --attack "$ATTACK" \
      --no-defense --provider "$provider" --model "$model" \
      || echo "!!! FAILED OFF $provider:$model $suite"

    curl -s -X POST "$SHIM/reset" >/dev/null   # fresh guard state per ON invocation
    echo ">>> [$provider:$model] $suite  GUARD ON   $(date +%H:%M:%S)"
    $PY run.py --suite "$suite" --user-tasks $USERS --security --attack "$ATTACK" \
      --sensitive-targets $SENS --egress-targets $EGRESS \
      --provider "$provider" --model "$model" \
      || echo "!!! FAILED ON $provider:$model $suite"
  done
done
echo "=== BREADTH SWEEP DONE $(date) ==="
