# Changelog

## Update — Bandit-integration crash fix + resilience pass

### 1. Fixed: crash the very first time real `bandit` is installed (the main bug)

**Root cause.** Real `bandit -f json` output has **no field for the enclosing
function name**. Its `test_name` field is the name of the *check* that
fired (e.g. `"blacklist"`, `"hardcoded_sql_expressions"`) — not a function
in your code. The previous build did:

```python
function=res.get("test_name", "?"),   # WRONG — this is the check name, not a function
```

Every later stage (`confirm_finding`, `_load_function_block`,
`get_full_block_source`, `apply_patch`) does `getattr(module,
finding.function)` or an AST search for a `FunctionDef` named
`finding.function`. Since `"blacklist"` isn't a real function in
`auth_utils.py`, the very first call crashed the whole run:

```
AttributeError: module 'auth_utils' has no attribute 'blacklist'
```

This reproduces on **any** machine that has `bandit` on `PATH` — it is not
an edge case, it fires on the shipped sample app every time. Verified by
writing a stub `bandit` CLI that emits real bandit's JSON schema and running
the original code against it (kept air-gapped, so real bandit couldn't be
installed to confirm the crash directly, but the JSON schema and the
`getattr` call site are unambiguous).

**Fix** (`kavach/detect.py`):
- Added `_enclosing_function(file_path, line_number)` — walks the file's
  real AST and returns the function whose body contains bandit's reported
  line. This is what should locate the function, not `test_name`.
- `_bandit_scan()` now resolves each bandit result's function this way. If
  a bandit finding lands on module-level or class-level code with **no**
  enclosing function (bandit works at line granularity, KAVACH's
  confirm/patch/verify pipeline is function-scoped by design), that finding
  is **skipped with a printed note**, not force-fed into a pipeline that
  can't handle it.
- Bandit's `filename` is absolute; it's now normalized to the same
  "relative to the working copy root" form the built-in scanner and every
  downstream stage already expect.
- The whole per-result loop is wrapped so one malformed bandit result can't
  take down the scan of every other finding.
- `confirm_finding()` also gained a defensive, clearly-worded check before
  the `getattr` call, in case a future rule/engine ever reports a name that
  isn't a top-level function (e.g. a method).

### 2. General resilience — "any new .py file" shouldn't be able to crash the run

Even with the bandit fix, the honest position is that a *tool integration*
and a *brand-new, unforeseen file* can both surprise a hand-built PoC. So
this pass also added defense-in-depth around every step that executes
real, untrusted code or subprocesses, rather than just papering over the
one bug that was found:

- `run_kavach.py` — the `detect.confirm_finding()` call, and the whole
  `reason.generate_patch()` + `verify.verify_patch()` attempt, are now
  wrapped in `try/except`. Any unexpected exception (missing dependency in
  a new file, unusual code shape, a flaky subprocess, etc.) now degrades
  that **one finding** to `ESCALATED` and the run continues to the next
  finding — it no longer kills the whole batch.
- `kavach/verify.py::verify_patch()` — `apply_patch`, `reconfirm_safe`, and
  `run_regression_suite` are each wrapped individually, so a malformed
  patch (e.g. unparseable code) or a `pytest` quirk produces a clean
  `FAIL` verdict with a readable reason instead of an unhandled traceback.
- `kavach/verify.py::_run_pytest()` — `subprocess.run` is now wrapped
  (`TimeoutExpired`/`OSError`), so a hung or misbehaving real `pytest`
  install falls back to the built-in `unittest` runner instead of crashing.
- `kavach/reason.py` — responses from a live cloud LLM call are stripped of
  ```` ```python ... ``` ```` code fences before being treated as raw
  source (a very common real failure mode once `ANTHROPIC_API_KEY` is
  actually set, since models often wrap code in fences even when told not
  to — this would otherwise be a guaranteed `ast.parse` failure on the
  first cloud-LLM patch).
- `kavach/report.py::build_bug_entry()` — `is_offline` now recognizes
  *any* `offline*` mode (including the new escalation/error modes), so an
  escalated finding is correctly labeled instead of misleadingly showing
  "Timed with a live cloud LLM API call."

### 3. Confirmed already working (no change needed)

You asked specifically whether CONFIRM/VERIFY were already
function-signature-agnostic. They were, before this pass:

- `kavach/detect.py::_build_call_args()` uses `inspect.signature(func)` to
  build call arguments from the *real* parameter names of whatever function
  is flagged — it does not hardcode `user_id`, `username`, `password`, etc.
- Verified this genuinely generalizes: dropped a brand-new file
  (`inventory_service.py`, different class/function/variable names for all
  three bug categories — crypto, SQLi, access-control) into `sample_app/`
  and reran `python run_kavach.py --target ./sample_app` with **no code
  changes**. All 3 new-file bugs were detected, confirmed by execution,
  patched, and verified — same as the 3 shipped samples.

**One honest caveat found during that same test, worth knowing about:**
the *offline* static-scan fallback (used when `bandit` isn't installed) is
still pattern-based — it looks for the literal shape `.execute(...DELETE
/UPDATE/INSERT...)` and `hashlib.md5/sha1(...)`. A DB layer calling its
method something other than `.execute()` won't be *detected* by the
built-in scanner (this is a DETECT-stage limitation, not a CONFIRM/VERIFY
one — once any engine produces a finding, CONFIRM/VERIFY handle it
generically regardless of names). Real `bandit`, when installed, doesn't
have this limitation for the rules it understands. This was already
implicitly disclosed in the README's "offline fallback, not the general
case" framing; flagging it explicitly here since it's the kind of caveat a
reviewer will ask about.

Also worth knowing: the built-in exploit-success heuristic in
`confirm_finding()` for `B-ACCESS-001` checks the handler's return value
against a fixed marker word list (`deleted`, `removed`, `updated`,
`success`, `"ok"`). A handler that returns a different word for
"destructive action succeeded" (e.g. `"purged"`) won't be flagged as
exploited by that heuristic. Not something this pass changed — noting it
as a known limitation of the offline confirm heuristic, separate from the
bandit crash fix, in case it matters for your evaluation.
