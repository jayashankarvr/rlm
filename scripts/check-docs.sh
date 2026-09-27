#!/usr/bin/env bash
# Checks the user docs against what the code does. Read-only.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { echo "check-docs: $*" >&2; exit 1; }

grep -qis "prevents system freezes" README.md CLAUDE.md gtk-gui/src/window.rs && fail "overclaim still present"
grep -n $'\xe2\x80\x94\|\xe2\x86\x92' README.md APPLICATION_LIMITING.md CHANGELOG.md CONTRIBUTING.md && fail "em-dash or arrow in user docs"
grep -q "rlm guard history" README.md || fail "README must show rlm guard history"
grep -q "journalctl --user -u rlm-guard" README.md || fail "README must show journalctl"
grep -q "cargo install --path cli" README.md || fail "README must show the source install that includes rlm-guard"
grep -q "cargo install rlmctl" README.md || fail "README must show the crates.io install"
grep -q "docs/assets/hero.svg" README.md || fail "README must show the hero image"
grep -q "How the guard stays safe" README.md || fail "README needs the guard safety FAQ"
grep -q "memory.swap.max" README.md || fail "README must document memory.high and memory.swap.max"
grep -rqE "user@\.service\.d/delegate\.conf" README.md APPLICATION_LIMITING.md common/src cli/src && fail "old drop-in name"
head -c 4 docs/assets/hero.svg | grep -q '<svg' && tail -c 8 docs/assets/hero.svg | grep -q '</svg>' || fail "hero.svg must be a complete SVG file"

# An empty config dir so the maintainer's own profiles do not affect the check.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
out="$(XDG_CONFIG_HOME="$tmp" cargo run -q -p rlmctl --bin rlm -- profiles)"
# rlm prints this note only when no custom profiles were loaded, so its absence
# means /etc/rlm/config.yaml added profiles and the list is not the built-ins.
grep -q "showing built-in presets" <<<"$out" || fail "custom profiles loaded (from /etc/rlm/config.yaml?); cannot check built-in profile names"
known="$(awk 'NR>2 && NF==5 {print tolower($1)}' <<<"$out")"
for p in $(grep -oE -- '--profile [A-Za-z]+' README.md APPLICATION_LIMITING.md | awk '{print tolower($2)}' | sort -u); do
  echo "$known" | grep -qx "$p" || fail "docs use unknown profile '$p'"
done
echo "check-docs: ok"
