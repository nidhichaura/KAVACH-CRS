"""
KAVACH-CRS — PATCH & SELF-VERIFY stage
Applies the proposed patch to the ACTUAL file on disk (inside the working
copy), re-confirms the original exploit is now blocked, then runs the full
regression suite. Only a patch that passes BOTH is accepted; otherwise the
orchestrator loops back to REASON with the failure reason.

Uses the real `pytest` CLI if installed; otherwise falls back to Python's
built-in `unittest` runner so verification still runs with zero installs.
"""
import ast
import importlib
import io
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from . import detect


def _split_imports(patched_source: str):
    """Separate any leading import lines from the actual function body, so
    repeated retries don't stack duplicate imports inline before the def."""
    lines = patched_source.splitlines(keepends=True)
    imports, body_start = [], 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(line.rstrip("\n"))
            body_start = i + 1
        elif stripped == "":
            body_start = i + 1
        else:
            break
    body = "".join(lines[body_start:])
    return imports, body


def get_full_block_source(target_dir: Path, finding) -> str:
    """Return the exact current source text for the flagged function,
    INCLUDING its decorator(s) — this is what generic patch generation
    operates on, so patches work regardless of the function/variable
    names actually used in the target file."""
    file_path = target_dir.parent / finding.file
    text = file_path.read_text()
    tree = ast.parse(text)
    lines = text.splitlines(keepends=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == finding.function:
            start = node.lineno - 1
            if node.decorator_list:
                start = node.decorator_list[0].lineno - 1
            end = node.end_lineno
            return "".join(lines[start:end])
    return ""


def apply_patch(target_dir: Path, finding, patched_source: str) -> Path:
    file_path = target_dir.parent / finding.file
    text = file_path.read_text()
    tree = ast.parse(text)

    new_imports, body = _split_imports(patched_source)

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == finding.function:
            start = node.lineno - 1
            if node.decorator_list:
                start = node.decorator_list[0].lineno - 1
            end = node.end_lineno
            lines = text.splitlines(keepends=True)
            new_lines = lines[:start] + [body if body.endswith("\n") else body + "\n"] + lines[end:]
            text = "".join(new_lines)
            break

    # add any new imports at the top, once, deduplicated against existing lines
    existing_lines = set(l.strip() for l in text.splitlines())
    to_add = [imp for imp in new_imports if imp.strip() not in existing_lines]
    if to_add:
        import_block = "\n".join(to_add) + "\n"
        insert_at = 0
        try:
            doc_tree = ast.parse(text)
            first = doc_tree.body[0] if doc_tree.body else None
            if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)):
                insert_at = first.end_lineno
        except SyntaxError:
            insert_at = 0
        lines = text.splitlines(keepends=True)
        text = "".join(lines[:insert_at]) + import_block + "".join(lines[insert_at:])

    file_path.write_text(text)
    return file_path


def _run_pytest(tests_dir: Path):
    if shutil.which("pytest") is None:
        return None
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(tests_dir), "-q"],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        # Real pytest install misbehaving (hung, missing plugin, etc.) —
        # don't crash the run, fall back to the built-in unittest runner.
        return None
    return proc.returncode == 0, proc.stdout[-2000:]


def _run_unittest(tests_dir: Path):
    loader = unittest.TestLoader()
    suite = loader.discover(str(tests_dir), pattern="test_*.py")
    buf = io.StringIO()
    runner = unittest.TextTestRunner(stream=buf, verbosity=1)
    result = runner.run(suite)
    return result.wasSuccessful(), buf.getvalue()


def run_regression_suite(target_dir: Path) -> tuple:
    tests_dir = target_dir / "tests"
    real = _run_pytest(tests_dir)
    if real is not None:
        return real
    # Clear cached modules so the freshly-patched file is re-imported, not
    # served from Python's import cache.
    for mod in list(sys.modules):
        if mod in ("auth_utils", "db_layer", "routes_user"):
            del sys.modules[mod]
    return _run_unittest(tests_dir)


def reconfirm_safe(target_dir: Path, finding) -> bool:
    """Re-run the same exploit harness from DETECT — it must now report
    'not exploited' for the patch to be considered fixed."""
    for mod in list(sys.modules):
        if mod in (Path(finding.file).stem,):
            del sys.modules[mod]
    result = detect.confirm_finding(target_dir, finding)
    return not result["exploited"]


def verify_patch(target_dir: Path, finding, patched_source: str) -> dict:
    # Every step below can legitimately throw on real-world input this PoC
    # didn't foresee — a malformed patch (e.g. a live LLM response that
    # isn't syntactically valid Python), a file that no longer parses, a
    # real `pytest`/tool quirk, etc. None of that should crash the whole
    # run: it should just count as "this attempt failed verification" so
    # the retry loop (or escalation) in run_kavach.py can handle it.
    try:
        apply_patch(target_dir, finding, patched_source)
    except Exception as e:
        return {
            "pass": False,
            "reason": f"Could not apply the proposed patch (invalid/unparseable code): {e}",
            "suite_output": "",
        }

    try:
        exploit_blocked = reconfirm_safe(target_dir, finding)
    except Exception as e:
        return {
            "pass": False,
            "reason": f"Re-running the exploit check against the patched file raised an error: {e}",
            "suite_output": "",
        }

    try:
        suite_ok, suite_output = run_regression_suite(target_dir)
    except Exception as e:
        return {
            "pass": False,
            "reason": f"Regression suite raised an unexpected error: {e}",
            "suite_output": "",
        }

    passed = exploit_blocked and suite_ok
    if not exploit_blocked:
        reason = "Patch did not block the original exploit — vulnerability still triggers."
    elif not suite_ok:
        reason = "Patch blocked the exploit but broke the regression suite."
    else:
        reason = "Original exploit blocked AND full regression suite passes."

    return {"pass": passed, "reason": reason, "suite_output": suite_output}
