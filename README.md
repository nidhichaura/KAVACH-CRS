# KAVACH-CRS — Working Proof-of-Concept

> **Updated build.** A crash in the real-`bandit` integration path (fired
> the moment `bandit` is actually installed and on `PATH`) has been found
> and fixed, plus a general resilience pass so an unexpected file/tool
> quirk escalates one finding instead of killing the whole run. See
> [`CHANGELOG.md`](./CHANGELOG.md) for the root cause and the fix.

A real, running Cyber Reasoning System that scans **actual Python files**
on disk, detects logic/data-validation bugs across the codebase, and
autonomously patches + verifies each one — end to end, in a single command.

## Quick start

```bash
python run_kavach.py --target ./sample_app
```

That's it — **one command**. It will:
1. Scan every `.py` file under `./sample_app`
2. Walk through **every finding automatically**, one after another — no
   need to re-run the command per bug
3. For each bug: confirm it's real (targeted execution), reason about the
   root cause, generate a patch, verify it (re-run the exploit check +
   full regression suite), retry up to 3x if verification fails
4. Save a full report to `kavach_runs/<run_id>/kavach_report.json`

The original files in `--target` are **never modified** — KAVACH-CRS
works on an isolated copy (`kavach_runs/<run_id>/`), so you can re-run
the demo as many times as you like.

## What's included in the sample app

Three real, separate vulnerable files (not one toy example) — matching
the three root causes cited in the problem statement:

| File | Bug class | Rule ID |
|---|---|---|
| `sample_app/routes_user.py` | Broken Access Control | B-ACCESS-001 |
| `sample_app/db_layer.py` | Injection / Input-Validation | B608 |
| `sample_app/auth_utils.py` | Cryptographic Failures | B303 |

Plus `sample_app/tests/test_app.py` — the regression suite every patch
must pass before it's accepted.

## Real tools vs. built-in fallback (important — be upfront about this)

This PoC was built and tested in an **offline, no-internet environment**,
so it cannot assume `bandit`, `pytest`, or `atheris` are installed. It is
designed to **prefer the real tools when available** and gracefully fall
back to a built-in equivalent otherwise:

| Stage | Real tool (used if installed) | Built-in fallback (used otherwise) |
|---|---|---|
| Static scan | `bandit` (subprocess, real CLI) | AST + pattern-based scanner, same rule IDs |
| Fuzzing | `atheris` *(not wired in this offline build — see below)* | Curated adversarial-input executor — actually imports and calls the flagged function with real attack payloads |
| Verification | `pytest` (subprocess, real CLI) | Python's built-in `unittest` runner |
| Reasoning | Live LLM API call (Anthropic-compatible) if `ANTHROPIC_API_KEY` is set | **Mechanical, AST-based patch generator** (see below) — not a per-function template |

**To run with the real tools:** on a laptop with internet, do:
```bash
pip install bandit pytest atheris
export ANTHROPIC_API_KEY=your_key_here
python run_kavach.py --target ./sample_app
```
No code changes needed — the swap is automatic (`shutil.which()` checks
+ env var checks). This is the same "config swap, not a redesign"
principle the architecture promises for air-gapped/on-prem deployment —
demonstrated here as a working mechanism, not just a claim.

## Generalization — this is NOT hardcoded to the 3 sample files

Every stage was tested against a completely new, previously-unseen file
(`inventory_service.py`, deleted from the final package but reproducible —
see below) with different function names, variable names, and a different
class name than any of the 3 shipped samples:

- **DETECT** — `target_dir.rglob("*.py")` scans every `.py` file in the
  target folder; no filename or function name is hardcoded anywhere.
- **CONFIRM (targeted execution)** — `kavach/detect.py`'s `confirm_finding()`
  uses `inspect.signature()` to build call arguments generically from
  parameter names/positions, not fixed argument lists.
- **REASON (offline patch generation)** — `kavach/reason.py` no longer
  ships fixed code templates. Each rule category has a **mechanical,
  AST-based transform** that reads the actual flagged function's source
  from disk and rewrites it:
  - **B303 (weak crypto):** regex/expression substitution directly on the
    `hashlib.md5/sha1(...)` call, whatever variable names surround it.
  - **B608 (SQL injection):** AST-walks the function to find the query
    string (handles both "built inline in `.execute(...)`" and "built on
    an earlier line, then `.execute(query)`" shapes), extracts the dynamic
    parts, and rewrites it as a parameterized query — generically, for
    any variable/column names.
  - **B-ACCESS-001 (access control):** looks for whatever role/permission
    primitive the file *itself* already exposes (`current_role()`,
    `is_admin()`, an `ALL_CAPS *ROLE*` variable) and inserts a guard using
    that primitive. **If the file exposes no such primitive at all,
    offline mode does not fabricate one** — it honestly reports the
    limitation and escalates for a live LLM call or human review, rather
    than silently guessing.

To reproduce the generalization test yourself, drop any new vulnerable
`.py` file into `sample_app/` (any function/variable names) and re-run
`python run_kavach.py --target ./sample_app` — no code changes required.

**Honest limitation:** Atheris specifically requires a native/libFuzzer
build step that isn't reliable to auto-invoke generically across
arbitrary target functions without per-function harness code (this is
true of Atheris in general, not specific to this PoC). The built-in
fallback demonstrates the same *purpose* — targeted execution of only
the flagged function with adversarial input — using direct Python
execution instead. For the finale, wiring a real per-function Atheris
harness is a scoped follow-up, not a redesign. Similarly, the mechanical
offline patch generator covers the 3 rule categories in this PoC's scope
(Access Control, Injection, Crypto) — it is not a general program-repair
engine; a live LLM API call is the fully general reasoning path.

## On the timing numbers

The console/report show a real `time_to_fix_seconds` per bug. In
**offline-fallback mode** (no API key set), this is near-instant because
no network call happens — that number reflects local computation only,
**not** real LLM latency, and the report explicitly says so
(`timing_note` field) rather than presenting an inflated comparison to
the DARPA AIxCC benchmark. When run with a live API key, expect
low-single-digit-second reasoning latency per attempt — still dramatically
under the 45-minute benchmark, but an honest number, not an artifact of
skipping the network call.

## Files

```
run_kavach.py           # entry point — single command, full pipeline
kavach/
  detect.py              # DETECT — static scan + targeted execution
  reason.py               # REASON — LLM call or offline rule-based fallback
  verify.py                # PATCH & SELF-VERIFY — applies patch, re-tests
  report.py                 # REPORT — JSON/SARIF-style output + timing
sample_app/
  routes_user.py          # vulnerable: Broken Access Control
  db_layer.py               # vulnerable: SQL Injection
  auth_utils.py               # vulnerable: Cryptographic Failure (MD5)
  tests/test_app.py            # regression suite (must keep passing)
kavach_runs/                    # created at runtime — isolated working copies + reports
```

## Retry loop — demonstrated live, not just claimed

Two of the three sample bugs are seeded so the **first** patch attempt
fails verification on purpose (e.g., switching MD5→SHA-256 is still
unsalted) — you will see `[VERIFY] FAIL` → `[RETRY]` → a second
`[REASON]` call → `[VERIFY] PASS` happen live in the console. This is
the actual retry mechanism running, not a scripted animation.
