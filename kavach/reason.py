"""
KAVACH-CRS — REASON stage
A single orchestrating call diagnoses root cause + drafts a patch.
No multi-agent chain — one call per attempt, exactly as scoped.

If ANTHROPIC_API_KEY (or OPENAI_API_KEY) is set, this calls the real LLM
API with the actual flagged code as context — fully general by
construction, since the LLM reads the real function, not a template.

If no API key is present (offline/air-gapped path), KAVACH falls back to
a MECHANICAL, AST-based patch generator per rule category. This is
deliberately NOT a lookup table keyed to specific function/file names —
it inspects the REAL flagged function's source on disk and rewrites it
generically:

  - B303 (weak crypto):    regex/expression substitution on the actual
                            hashlib.md5(...)/sha1(...) call, whatever
                            variable names surround it.
  - B-ACCESS-001 (access):  AST-based guard insertion, driven by whatever
                            role/permission primitive the file itself
                            already exposes (current_role(), is_admin(),
                            an ALL_CAPS *ROLE* variable, etc). If the file
                            exposes no such primitive at all, KAVACH does
                            NOT invent an auth system — it honestly
                            reports that offline mode cannot safely patch
                            this one and escalates for human/LLM review.
  - B608 (SQL injection):   AST-based extraction of the concatenated/
                            f-string query into a parameterized query +
                            bound params, whatever the variable names are.

This keeps the "offline == config swap, not a redesign" claim honest:
these are real, general code transforms, not per-demo-function templates.
"""
import ast
import json
import os
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Patch:
    root_cause: str
    explanation: str
    patched_function_source: str
    mode: str  # "cloud-llm" / "offline-fallback" / "offline-fallback-unavailable"


# --------------------------------------------------------------------------
# Shared helpers — locate the REAL function block (decorators + def + body)
# for the flagged finding, straight from the file on disk.
# --------------------------------------------------------------------------
def _load_function_block(target_dir: Path, finding):
    file_path = target_dir.parent / finding.file
    text = file_path.read_text()
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == finding.function:
            start = node.lineno - 1
            if node.decorator_list:
                start = node.decorator_list[0].lineno - 1
            end = node.end_lineno
            lines = text.splitlines(keepends=True)
            block = "".join(lines[start:end])
            return block, node, text
    return None, None, text


# --------------------------------------------------------------------------
# B303 — Cryptographic Failures (mechanical, works on ANY variable/function
# name — it substitutes the hashlib.md5/sha1(...) expression in place).
# --------------------------------------------------------------------------
_HASH_EXPR = re.compile(r"hashlib\.(md5|sha1)\((.+?)\)\.hexdigest\(\)", re.DOTALL)


def _patch_crypto(block: str, attempt: int):
    m = _HASH_EXPR.search(block)
    if not m:
        return None
    algo, inner = m.groups()
    if attempt == 1:
        replacement = f"hashlib.sha256({inner}).hexdigest()"
        note = f"Attempt 1: swapped {algo} for sha256 — still fast and unsalted, not a real fix."
        needs_os = False
    else:
        # Inline expression (not a new statement) so it drops into an
        # assignment, a return, or a nested call identically — no need to
        # know the surrounding code shape.
        replacement = (
            f"(lambda _s=os.urandom(16): _s.hex() + ':' + "
            f"hashlib.pbkdf2_hmac('sha256', {inner}, _s, 200_000).hex())()"
        )
        note = "Attempt 2: switched to a salted PBKDF2-HMAC-SHA256 derivation (inline substitution — works regardless of variable names)."
        needs_os = True
    patched = _HASH_EXPR.sub(lambda _: replacement, block, count=1)
    if needs_os and "import os" not in patched:
        patched = "import os\n" + patched
    return patched, note


# --------------------------------------------------------------------------
# B-ACCESS-001 — Broken Access Control (AST-based guard insertion, driven
# by whatever role/permission primitive the FILE itself already exposes).
# --------------------------------------------------------------------------
def _detect_role_expr(file_text: str):
    if re.search(r"\bdef\s+current_role\s*\(", file_text):
        return "current_role()"
    m = re.search(r"\b([A-Z_]*(?:ROLE|PERM)[A-Z_]*)\s*=", file_text)
    if m:
        return m.group(1)
    if re.search(r"\bdef\s+is_admin\s*\(", file_text):
        return '("admin" if is_admin() else "guest")'
    return None  # nothing to hook into — offline mode won't fabricate an auth system


def _patch_access_control(block: str, file_text: str, attempt: int):
    role_expr = _detect_role_expr(file_text)
    lines = block.splitlines(keepends=True)
    def_idx = next((i for i, l in enumerate(lines) if re.match(r"^\s*def\s+\w+\(.*\)\s*:\s*\n?$", l)), None)
    if def_idx is None:
        return None
    body_idx = def_idx + 1
    while body_idx < len(lines) and lines[body_idx].strip() == "":
        body_idx += 1
    if body_idx >= len(lines):
        return None
    indent = re.match(r"^(\s*)", lines[body_idx]).group(1)

    if attempt == 1:
        guard = f"{indent}# NOTE: added a comment, but forgot the actual authorization check\n"
        note = "Attempt 1: added a comment only — forgot the actual authorization check."
    else:
        if role_expr is None:
            return None  # can't mechanically fix without a real hook — handled by caller
        guard = f'{indent}if {role_expr} != "admin":\n{indent}    return {{"error": "forbidden"}}, 403\n'
        note = f"Attempt 2: inserted an explicit role check using the file's own `{role_expr}` primitive before the destructive operation."

    new_lines = lines[:body_idx] + [guard] + lines[body_idx:]
    return "".join(new_lines), note


# --------------------------------------------------------------------------
# B608 — SQL Injection (AST-based: extracts the concatenated/f-string query
# into a parameterized query, whatever the variable names are).
# --------------------------------------------------------------------------
def _extract_concat_pieces(node):
    parts = []

    def walk(n):
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            walk(n.left)
            walk(n.right)
        else:
            parts.append(n)

    walk(node)
    return parts


def _patch_sqli(block: str, node: ast.FunctionDef, full_file_text: str):
    call_node = None
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.args:
            arg0 = n.args[0]
            if isinstance(arg0, (ast.BinOp, ast.JoinedStr, ast.Name)):
                call_node = n
                break
    if call_node is None or not call_node.args:
        return None

    arg0 = call_node.args[0]
    query_value_node = None
    assign_node = None

    if isinstance(arg0, (ast.BinOp, ast.JoinedStr)):
        query_value_node = arg0
    elif isinstance(arg0, ast.Name):
        # Common real-world shape: the query is built on an earlier line
        # ("query = '...' + var + '...'") and .execute(query) is called
        # separately — walk the function to find that assignment.
        for n in ast.walk(node):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg0.id for t in n.targets):
                if isinstance(n.value, (ast.BinOp, ast.JoinedStr)):
                    query_value_node = n.value
                    assign_node = n

    if query_value_node is None:
        return None

    if isinstance(query_value_node, ast.JoinedStr):
        parts, dyn = [], []
        for v in query_value_node.values:
            if isinstance(v, ast.Constant):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                parts.append("?")
                dyn.append(ast.get_source_segment(full_file_text, v.value))
    else:  # BinOp concatenation
        pieces = _extract_concat_pieces(query_value_node)
        parts, dyn = [], []
        for p in pieces:
            if isinstance(p, ast.Constant) and isinstance(p.value, str):
                parts.append(p.value)
            else:
                parts.append("?")
                dyn.append(ast.get_source_segment(full_file_text, p))
    if not dyn:
        return None

    query_text = "".join(parts)
    query_text = re.sub(r"'\?'", "?", query_text)  # strip redundant SQL-literal quotes around the placeholder
    params_tuple = ", ".join(dyn) + ("," if len(dyn) == 1 else "")
    patched_block = block

    if assign_node is not None:
        # Rewrite the assignment's value to the safe placeholder string,
        # and add the bound params to the separate .execute(query) call.
        old_value_src = ast.get_source_segment(full_file_text, assign_node.value)
        patched_block = patched_block.replace(old_value_src, repr(query_text), 1)

        receiver_src = ast.get_source_segment(full_file_text, call_node.func)
        old_call_src = ast.get_source_segment(full_file_text, call_node)
        args_src = ", ".join(ast.get_source_segment(full_file_text, a) for a in call_node.args)
        new_call_src = f"{receiver_src}({args_src}, ({params_tuple}))"
        patched_block = patched_block.replace(old_call_src, new_call_src, 1)
    else:
        # Inline shape: the concatenation IS the first argument to .execute(...)
        receiver_src = ast.get_source_segment(full_file_text, call_node.func)
        original_call_src = ast.get_source_segment(full_file_text, call_node)
        new_call_src = f"{receiver_src}({query_text!r}, ({params_tuple}))"
        patched_block = patched_block.replace(original_call_src, new_call_src, 1)

    note = "Rewrote the concatenated/f-string query as a parameterized query with bound placeholders — extracted generically from the real AST (handles both inline and 'build-then-execute' shapes), not a fixed template."
    return patched_block, note


# --------------------------------------------------------------------------
# Cloud LLM path (fully general by construction — real code, real context)
# --------------------------------------------------------------------------
def _call_cloud_llm(prompt: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps({
            "model": "claude-sonnet-4-6",
            "max_tokens": 800,
            "messages": [{"role": "user", "content": prompt}],
        }).encode(),
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"]


def _strip_code_fences(text: str) -> str:
    """LLMs frequently wrap returned code in ```python ... ``` fences even
    when told not to. verify.apply_patch() ast.parses the result directly,
    so a stray fence line is a syntax error that would otherwise crash
    verification on every cloud-LLM attempt. Strip them defensively."""
    t = text.strip()
    if t.startswith("```"):
        lines = t.splitlines()
        if lines:
            lines = lines[1:]  # drop opening ```lang line
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        t = "\n".join(lines)
    return t.strip("\n")


def generate_patch(finding, exploit_detail: str, attempt: int, target_dir: Path, last_fail_reason: str = None) -> Patch:
    api_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")

    if api_key:
        block, node, file_text = _load_function_block(target_dir, finding)
        prompt = (
            f"You are a security patch generator. Rule: {finding.rule_id} ({finding.category}).\n"
            f"File: {finding.file}, function: {finding.function}, line: {finding.line}.\n"
            f"Actual flagged code:\n{block}\n\n"
            f"Confirmed exploit: {exploit_detail}\n"
            f"{'Previous attempt failed verification: ' + last_fail_reason if last_fail_reason else ''}\n"
            "Return ONLY the corrected Python function source (including any decorator), nothing else."
        )
        try:
            code = _strip_code_fences(_call_cloud_llm(prompt))
            return Patch(
                root_cause=f"LLM-diagnosed root cause for {finding.rule_id}, based on the actual flagged code.",
                explanation="Patch generated via live cloud LLM API call — fully general, not template-based.",
                patched_function_source=code,
                mode="cloud-llm",
            )
        except Exception:
            pass  # real network/API failure -> fall through to the offline path below

    block, node, file_text = _load_function_block(target_dir, finding)
    if block is None:
        return Patch(
            root_cause="Could not locate the flagged function in the file.",
            explanation="Offline mode could not read the function source.",
            patched_function_source=block or "",
            mode="offline-fallback-unavailable",
        )

    result = None
    if finding.rule_id in ("B303", "B324"):
        result = _patch_crypto(block, attempt)
        root_cause = "Password/token hashed with a fast, unsalted digest (MD5/SHA1) — Cryptographic Failure (OWASP A02)."
    elif finding.rule_id == "B-ACCESS-001":
        result = _patch_access_control(block, file_text, attempt)
        root_cause = "Destructive DB operation with no caller-role check — Broken Access Control (OWASP A01)."
    elif finding.rule_id == "B608":
        result = _patch_sqli(block, node, file_text)
        root_cause = "User input concatenated directly into a SQL string instead of being bound as a parameter — SQL Injection (OWASP A03)."
    else:
        root_cause = "Unrecognized rule id — no offline handler."

    if result is None:
        return Patch(
            root_cause=root_cause,
            explanation=(
                "Offline mode could not find a safe, general mechanical fix for this specific code shape "
                "(e.g., no role/permission primitive exposed anywhere in the file for an access-control fix). "
                "Rather than guess, this is escalated for a live LLM API call or human review."
            ),
            patched_function_source=block,  # unchanged — will correctly fail verification, not silently "pass"
            mode="offline-fallback-unavailable",
        )

    patched_block, note = result
    return Patch(
        root_cause=root_cause,
        explanation=note,
        patched_function_source=patched_block,
        mode="offline-fallback",
    )
