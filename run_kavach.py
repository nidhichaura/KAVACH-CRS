#!/usr/bin/env python3
"""
KAVACH-CRS — Cyber Reasoning System
Single command. Scans the ENTIRE target directory, then automatically
walks through every finding — detect -> confirm -> reason -> verify -> report
— one after another, with no user interaction required between bugs.

Usage:
    python run_kavach.py --target ./sample_app
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kavach import detect, reason, verify, report

MAX_ATTEMPTS = 3
C = {
    "hdr": "\033[1;36m", "ok": "\033[1;32m", "err": "\033[1;31m",
    "dim": "\033[2m", "amber": "\033[1;33m", "reset": "\033[0m", "bold": "\033[1m",
}


def c(txt, color):
    return f"{C[color]}{txt}{C['reset']}"


def make_working_copy(target: str) -> Path:
    """Operate on an isolated copy so the original repo is never mutated
    mid-demo, and the run is safely re-runnable."""
    src = Path(target).resolve()
    run_id = time.strftime("run_%Y%m%d_%H%M%S")
    work_root = Path(__file__).parent / "kavach_runs" / run_id
    work_dir = work_root / src.name
    shutil.copytree(src, work_dir)
    return work_dir


def main():
    parser = argparse.ArgumentParser(description="KAVACH-CRS — autonomous Cyber Reasoning System")
    parser.add_argument("--target", required=True, help="Path to the Python codebase to scan")
    args = parser.parse_args()

    run_start = time.time()
    print(c("=" * 70, "dim"))
    print(c("KAVACH-CRS", "bold") + "  —  autonomous detect -> patch -> verify pipeline")
    print(c("=" * 70, "dim"))

    work_dir = make_working_copy(args.target)
    print(f"[INPUT]  Target: {args.target}")
    print(f"[INPUT]  Working copy (original left untouched): {work_dir}\n")

    # ---------------- DETECT (whole codebase, real files) ----------------
    print(c("[DETECT]", "amber") + " Scanning entire target directory...")
    findings = detect.static_scan(work_dir)
    files_scanned = len(list(work_dir.rglob("*.py")))
    engine = findings[0].engine.split(" ")[0] if findings else "n/a"
    print(f"[DETECT] Scanned {files_scanned} file(s) using: {engine}")
    print(f"[DETECT] {len(findings)} finding(s) across the codebase:\n")
    for f in findings:
        print(f"    - {f.rule_id:14s} {f.file}:{f.line}  ({f.category}) in {f.function}()")
    print()

    if not findings:
        print(c("No issues found. Nothing to patch.", "ok"))
        return

    bug_entries = []

    # ---------------- Process every finding, one after another, automatically ----------------
    for idx, finding in enumerate(findings, 1):
        bug_start = time.time()
        print(c("-" * 70, "dim"))
        print(c(f"BUG {idx}/{len(findings)}", "bold") + f"  {finding.rule_id}  {finding.file}:{finding.line}  ({finding.category})")
        print(c("-" * 70, "dim"))

        # --- confirm via targeted execution ("fuzz") ---
        # This step imports and calls real code from the target file, so on
        # a genuinely new/unseen file it can legitimately hit things this
        # PoC's harness can't handle (missing dependency, a method instead
        # of a top-level function, an unexpected signature shape, ...).
        # That must never take down the whole run -- it should escalate
        # just this one finding and move on to the next.
        try:
            exploit = detect.confirm_finding(work_dir, finding)
        except Exception as e:
            print(f"  " + c(f"[FUZZ]   ERROR — could not confirm this finding: {e}", "err"))
            print(f"  " + c("[REPORT] ESCALATED (confirmation error — needs manual review)", "err"))
            print()
            placeholder_exploit = {"exploited": None, "detail": f"Targeted execution raised an exception: {e}"}
            placeholder_patch = reason.Patch(
                root_cause="Not determined — confirmation step failed before reasoning could run.",
                explanation="See exploit_confirmation for the underlying error.",
                patched_function_source="",
                mode="offline-fallback-unavailable",
            )
            placeholder_verdict = {"pass": False, "reason": f"Confirmation step raised an exception: {e}"}
            bug_entries.append(
                report.build_bug_entry(finding, placeholder_exploit, placeholder_patch, placeholder_verdict, 0, time.time() - bug_start)
            )
            continue
        status = c("EXPLOITED", "err") if exploit["exploited"] else c("safe", "ok")
        print(f"  [FUZZ]   Targeted execution on {finding.function}() -> {status}")
        print(f"  [FUZZ]   {exploit['detail']}")

        # --- reason + verify loop ---
        attempt = 0
        verified = False
        last_fail_reason = None
        patch = None
        verdict = None

        # Snapshot the original (unpatched) source once, so every retry
        # attempt reasons about and patches the SAME original code — not
        # a version already mutated by a previous failed attempt.
        bug_file_path = work_dir.parent / finding.file
        original_source = bug_file_path.read_text()

        while attempt < MAX_ATTEMPTS and not verified:
            attempt += 1
            bug_file_path.write_text(original_source)  # reset to pristine before each attempt
            print(f"  [REASON] Attempt {attempt}/{MAX_ATTEMPTS} — single orchestrating LLM call...")
            try:
                patch = reason.generate_patch(finding, exploit["detail"], attempt, work_dir, last_fail_reason)
                print(f"  [REASON] mode: {patch.mode}")
                print(f"  [REASON] root cause: {patch.root_cause}")

                print(f"  [VERIFY] Applying patch, re-running exploit check + full regression suite...")
                verdict = verify.verify_patch(work_dir, finding, patch.patched_function_source)
            except Exception as e:
                # verify.verify_patch already catches its own internal
                # errors and returns a fail-verdict; this outer guard is
                # for anything unexpected from reason.generate_patch
                # itself (e.g. a real network error mid-call that wasn't
                # already swallowed) so a single bad attempt degrades to
                # a normal retry/escalation instead of killing the run.
                print(f"  " + c(f"[ERROR]  Attempt {attempt} raised an unexpected exception: {e}", "err"))
                last_fail_reason = f"Unexpected exception during reason/verify: {e}"
                if patch is None:
                    patch = reason.Patch(
                        root_cause="Not determined — an unexpected exception interrupted this attempt.",
                        explanation=str(e),
                        patched_function_source="",
                        mode="offline-fallback-unavailable",
                    )
                verdict = {"pass": False, "reason": last_fail_reason}
                if attempt < MAX_ATTEMPTS:
                    print(f"  " + c(f"[RETRY]  Looping back to REASON (retry {attempt}/{MAX_ATTEMPTS-1})...", "amber"))
                continue

            if verdict["pass"]:
                verified = True
                print(f"  " + c("[VERIFY] PASS", "ok") + f" — {verdict['reason']}")
            else:
                print(f"  " + c("[VERIFY] FAIL", "err") + f" — {verdict['reason']}")
                last_fail_reason = verdict["reason"]
                if attempt < MAX_ATTEMPTS:
                    print(f"  " + c(f"[RETRY]  Looping back to REASON (retry {attempt}/{MAX_ATTEMPTS-1})...", "amber"))

        bug_elapsed = time.time() - bug_start
        if not verified:
            bug_file_path.write_text(original_source)  # leave a clean, unpatched file for escalated bugs
        outcome = c("VERIFIED & FIXED", "ok") if verified else c("ESCALATED (manual review)", "err")
        speed_tag = "offline-fallback timing (no live API latency)" if patch.mode == "offline-fallback" else f"~{report.DARPA_BENCHMARK_SECONDS / bug_elapsed:.0f}x faster than the 45-min DARPA AIxCC benchmark"
        print(f"  [REPORT] {outcome}  —  time to fix: {bug_elapsed:.2f}s ({speed_tag})")
        print()

        bug_entries.append(
            report.build_bug_entry(finding, exploit, patch, verdict, attempt, bug_elapsed)
        )

    total_elapsed = time.time() - run_start
    run_report = report.build_run_report(args.target, bug_entries, total_elapsed, files_scanned)
    out_path = work_dir.parent / "kavach_report.json"
    report.save_report(run_report, out_path)

    print(c("=" * 70, "dim"))
    print(c("RUN COMPLETE", "bold"))
    print(c("=" * 70, "dim"))
    print(f"  Files scanned        : {files_scanned}")
    print(f"  Bugs found            : {len(bug_entries)}")
    print(f"  Bugs verified & fixed : {run_report['summary']['bugs_verified_fixed']}")
    print(f"  Bugs escalated        : {run_report['summary']['bugs_escalated']}")
    print(f"  Total time            : {total_elapsed:.2f}s")
    print(f"  Avg time / bug        : {run_report['summary']['avg_time_per_bug_seconds']:.2f}s")
    print(f"  Report saved to       : {out_path}")
    print(c("=" * 70, "dim"))


if __name__ == "__main__":
    main()
