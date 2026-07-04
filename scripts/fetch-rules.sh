#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
RULESETS="$ROOT/rulesets"
mkdir -p "$RULESETS"

clone_pinned() {
  name=$1
  url=$2
  revision=$3
  sparse_path=${4:-}
  destination="$RULESETS/$name"

  if [ -e "$destination" ]; then
    if [ -d "$destination/.git" ] && [ "$(git -C "$destination" rev-parse HEAD 2>/dev/null || true)" = "$revision" ]; then
      printf '%s\n' "[ok] $name already at $revision"
      return
    fi
    printf '%s\n' "[error] $destination exists and is not the pinned checkout." >&2
    printf '%s\n' "        Remove it explicitly before fetching again." >&2
    exit 1
  fi

  printf '%s\n' "[fetch] $name"
  git clone --filter=blob:none --no-checkout --depth 1 "$url" "$destination"
  if [ -n "$sparse_path" ]; then
    git -C "$destination" sparse-checkout init --cone
    git -C "$destination" sparse-checkout set "$sparse_path"
  fi
  git -C "$destination" fetch --depth 1 origin "$revision"
  git -C "$destination" checkout --detach "$revision"
}

clone_pinned yara-rules \
  https://github.com/Yara-Rules/rules.git \
  0f93570194a80d2f2032869055808b0ddcdfb360

clone_pinned protections-artifacts \
  https://github.com/elastic/protections-artifacts.git \
  9a00306e5cccfb553949aae393a5cacfdedbda4c \
  yara/rules

clone_pinned cobaltstrike-yara \
  https://github.com/Te-k/cobaltstrike.git \
  9ac4d5d931b6228a8b17dbcb336ad915acf7d41f

clone_pinned detect-it-easy \
  https://github.com/horsicq/Detect-It-Easy.git \
  3aa0b315a6e71946f5ca5cc9f8d1335b026d61c4 \
  yara_rules

clone_pinned sigma \
  https://github.com/SigmaHQ/sigma.git \
  941c27449146f1afb95f2ea36b2b4528d988dfbe \
  rules

printf '%s\n' "Rule repositories are ready in $RULESETS"
