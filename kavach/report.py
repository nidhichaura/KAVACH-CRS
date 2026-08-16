"""
KAVACH-CRS — REPORT stage
Builds one structured JSON/SARIF-compatible entry per bug, plus a run-level
summary that reports total/average time per fix against the DARPA AIxCC
benchmark ($152 / 45 min per fix) — the same yardstick cited in the pitch.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

DARPA_BENCHMARK_SECONDS = 45 * 60  # 45 minutes


def build_bug_entry(finding, exploit, patch, verdict, attempts, elapsed_seconds):
    is_offline = patch.mode.startswith("offline")
    speed_note = (
        "Offline-fallback mode used a local rule table, not a live LLM API call — "
        "this timing does NOT include real network/API latency and should not be "
        "compared directly to the DARPA benchmark. With a live cloud LLM API call, "
        "expect low single-digit-second reasoning latency per attempt, still far "
        "under the 45-min benchmark."
        if is_offline else
        "Timed with a live cloud LLM API call."
    )
    entry = {
        "id": finding.rule_id,
        "category": finding.category,
        "file": finding.file,
        "function": finding.function,
        "line": finding.line,
        "message": finding.message,
        "detection_engine": finding.engine,
        "exploit_confirmation": exploit["detail"],
        "reasoning": {
            "attempts": attempts,
            "mode_used": patch.mode,
            "root_cause": patch.root_cause,
            "explanation": patch.explanation,
        },
        "verification": {
            "status": "VERIFIED" if verdict["pass"] else "FAILED_ALL_ATTEMPTS",
            "reason": verdict["reason"],
        },
        "time_to_fix_seconds": round(elapsed_seconds, 2),
        "timing_note": speed_note,
        "sign_off": "Ready for human reviewer sign-off." if verdict["pass"] else "Escalated — needs manual engineering review.",
    }
    if not is_offline:
        entry["faster_than_darpa_benchmark_by_x"] = round(DARPA_BENCHMARK_SECONDS / elapsed_seconds, 1) if elapsed_seconds > 0 else None
    return entry


def build_run_report(target: str, bug_entries: list, total_elapsed: float, files_scanned: int) -> dict:
    fixed = sum(1 for b in bug_entries if b["verification"]["status"] == "VERIFIED")
    return {
        "tool": "KAVACH-CRS",
        "schema": "kavach-crs/1.0 (SARIF-compatible subset)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "files_scanned": files_scanned,
            "bugs_found": len(bug_entries),
            "bugs_verified_fixed": fixed,
            "bugs_escalated": len(bug_entries) - fixed,
            "total_time_seconds": round(total_elapsed, 2),
            "avg_time_per_bug_seconds": round(total_elapsed / len(bug_entries), 2) if bug_entries else 0,
            "darpa_aixcc_benchmark_seconds_per_bug": DARPA_BENCHMARK_SECONDS,
        },
        "findings": bug_entries,
    }


def save_report(report: dict, out_path: Path) -> Path:
    out_path.write_text(json.dumps(report, indent=2))
    return out_path
