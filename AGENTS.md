# AGENTS.md


## 1. Documentation Rules

Docs describe the system **as it is now**. History, process, and change narratives belong in PRs / commits / ADRs — not here.

### Don't write

- **Change narrative**: "was X, now Y"; "adjusted because of Z"; "as requested by N"
- **Temporal words**: now / recently / newly / "as of vX"; 中文：新增了 / 现已支持 / 之前 / 原本
- **Process artifacts**: task splits, debug logs, file lists, verification steps, options considered
- **Preambles**: "This document introduces..."; "The following changes..."

### Don't create

No new doc without an explicit request.

### When updating

Rewrite the whole section. Delete what is replaced. Never keep two versions side by side.

### Self-check

Read every sentence as a first-time reader. If removing the timestamp or context makes it false, delete it.

## 2. Comment Rules

- Write code that speaks for itself. Comment only when necessary to explain **WHY**, not WHAT. We do not need comments most of the time.
- ❌ AVOID — **Obvious Comments**(复述代码)、**Redundant Comments**、**Outdated Comments**、**Commented-out Code**、**Changelog Comments**、**Divider Comments**


## 3. Verify Before Done

- Build:  `make build`           
- Test:   `make test`

## 4. Code Style Rules

- No `type X = Y` aliases. Use the underlying type directly; don't keep aliases for backward-compat names.
- Test merges: when tests conflict in a rebase, prefer rewriting over mechanical 3-way merge.

