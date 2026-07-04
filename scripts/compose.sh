#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ -d rulesets/yara-rules ] && [ -d rulesets/sigma/rules ]; then
  exec docker compose -f compose.yaml -f compose.rules.yaml "$@"
fi

printf '%s\n' "[notice] Community rules are not initialized; starting with bundled local rules." >&2
printf '%s\n' "         Run ./scripts/fetch-rules.sh to enable the full rule set." >&2
exec docker compose -f compose.yaml "$@"
