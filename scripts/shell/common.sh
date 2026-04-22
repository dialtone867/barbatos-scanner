#!/usr/bin/env bash
# common.sh — Shared utilities sourced by all BARBATOS shell scripts.
# Safe to source multiple times.

# Guard against repeated sourcing
[[ -n "${_BARBATOS_COMMON_LOADED:-}" ]] && return 0

# ── ANSI colour palette ────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
export RED GREEN YELLOW BLUE PURPLE CYAN WHITE NC

# ── Resolve BARBATOS runtime version ──────────────────────────────────────────
# Sets BARBATOS_VERSION (exported).
# Priority: inherited env → git tag → VERSION file → hardcoded fallback.
# Optional arg $1: explicit repo root path. If omitted, walks up from this file.
resolve_barbatos_version() {
    if [[ -n "${BARBATOS_VERSION:-}" ]] && [[ "${BARBATOS_VERSION}" != "unknown" ]]; then
        return 0
    fi

    local root="${1:-}"
    if [[ -z "$root" ]]; then
        local dir
        dir="$(cd "$(dirname "${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}")" && pwd)"
        while [[ "$dir" != "/" && "$dir" != "." ]]; do
            if [[ -d "$dir/.git" || -f "$dir/VERSION" ]]; then
                root="$dir"
                break
            fi
            dir="$(dirname "$dir")"
        done
    fi

    BARBATOS_VERSION=""
    if [[ -n "$root" && -d "$root/.git" ]]; then
        BARBATOS_VERSION=$(cd "$root" && git describe --tags --always 2>/dev/null || true)
    fi
    if [[ -z "$BARBATOS_VERSION" && -n "$root" && -f "$root/VERSION" ]]; then
        BARBATOS_VERSION=$(tr -d '[:space:]' < "$root/VERSION")
    fi
    if [[ -z "$BARBATOS_VERSION" ]]; then
        BARBATOS_VERSION="2.7.0"
    fi
    export BARBATOS_VERSION
}

_BARBATOS_COMMON_LOADED=1
export _BARBATOS_COMMON_LOADED
