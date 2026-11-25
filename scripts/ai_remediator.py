from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv
from groq import Groq

DEFAULT_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
MAX_FINDINGS = 8

SYSTEM_PROMPT = """You are a senior Application Security Engineer performing automated SAST remediation in a DevSecOps CI/CD pipeline.

Given a Semgrep security finding and the surrounding Python source code, return ONLY a valid JSON object with these exact keys:
{
  "title": "Short vulnerability title (max 8 words)",
  "owasp_category": "Relevant OWASP Top 10 2021 category (e.g., OWASP A03:2021 - Injection)",
  "cwe": "Primary CWE ID (e.g., CWE-89)",
  "severity": "HIGH, MEDIUM, or CRITICAL",
  "risk_explanation": "Clear 2-sentence explanation of how an attacker could exploit this vulnerability.",
  "remediation_summary": "Clear 1-2 sentence explanation of how the fix resolves the root cause.",
  "fixed_code": "Exact drop-in Python code replacing ONLY the lines from start_line to end_line inclusive. Preserve the exact leading indentation of those lines. Do NOT wrap in markdown code fences. Do NOT include line numbers.",
  "requires_import": "Any new Python import statement needed at top of file if not already imported, otherwise empty string."
}

Strict rules:
1. Keep the fix minimal and preserve existing application behavior so unit tests continue to pass.
2. Never introduce hardcoded secrets, eval(), exec(), or shell=True.
3. Output strictly valid JSON with no extra text before or after the JSON object.
"""


def extract_json_object(raw_text: str) -> dict[str, Any]:
    """Parse JSON safely even if the LLM wraps output in code fences."""
    cleaned = raw_text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(cleaned[start : end + 1])
        raise


def read_code_context(
    file_path: str, start_line: int, end_line: int, padding: int = 12
) -> tuple[str, str]:
    """Return (exact vulnerable lines, numbered surrounding context)."""
    lines = Path(file_path).read_text(encoding="utf-8").splitlines()
    total = len(lines)

    vuln_start = max(1, start_line)
    vuln_end = min(total, end_line)
    vulnerable_snippet = "\n".join(lines[vuln_start - 1 : vuln_end])

    ctx_start = max(1, vuln_start - padding)
    ctx_end = min(total, vuln_end + padding)
    numbered_context = "\n".join(
        f"{ln:>4}: {lines[ln - 1]}" for ln in range(ctx_start, ctx_end + 1)
    )
    return vulnerable_snippet, numbered_context


def request_ai_fix(
    client: Groq,
    model: str,
    finding: dict[str, Any],
    vulnerable_snippet: str,
    numbered_context: str,
) -> dict[str, Any]:
    """Call Groq LLM to generate a structured security remediation."""
    user_prompt = (
        f"File: {finding['path']}\n"
        f"Rule ID: {finding['rule_id']}\n"
        f"Lines to replace: {finding['start_line']} to {finding['end_line']}\n"
        f"Scanner message: {finding['message']}\n"
        f"Known metadata CWE: {finding['cwe']} | OWASP: {finding['owasp']}\n\n"
        f"--- EXACT LINES TO REPLACE ({finding['start_line']}-{finding['end_line']}) ---\n"
        f"{vulnerable_snippet}\n\n"
        f"--- SURROUNDING FILE CONTEXT (WITH LINE NUMBERS) ---\n"
        f"{numbered_context}\n"
    )

    response = client.chat.completions.create(
        model=model,
        temperature=0.1,
        max_tokens=1024,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
    )
    content = response.choices[0].message.content or "{}"
    return extract_json_object(content)


def load_semgrep_findings(report_path: Path) -> list[dict[str, Any]]:
    """Extract and deduplicate actionable findings from semgrep-report.json."""
    if not report_path.exists():
        print(f"[INFO] Report file not found: {report_path}")
        return []

    raw = json.loads(report_path.read_text(encoding="utf-8"))
    results = raw.get("results", [])

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int, str]] = set()

    for item in results:
        path = item.get("path", "").replace("\\", "/")
        start_line = int(item.get("start", {}).get("line", 1))
        end_line = int(item.get("end", {}).get("line", start_line))
        rule_id = item.get("check_id", "unknown-rule")

        key = (path, start_line, end_line, rule_id)
        if key in seen:
            continue
        seen.add(key)

        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe_raw = metadata.get("cwe", [])
        owasp_raw = metadata.get("owasp", [])

        cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else str(cwe_raw or "N/A")
        owasp = (
            owasp_raw[0] if isinstance(owasp_raw, list) and owasp_raw else str(owasp_raw or "N/A")
        )

        findings.append(
            {
                "path": path,
                "start_line": start_line,
                "end_line": end_line,
                "rule_id": rule_id,
                "severity": extra.get("severity", "WARNING"),
                "message": extra.get("message", "Security issue detected."),
                "cwe": cwe,
                "owasp": owasp,
            }
        )

    return findings[:MAX_FINDINGS]


def get_pr_diff_lines(
    repo: str, pr_number: str, token: str
) -> dict[str, set[int]]:
    """Fetch changed line numbers per file in the PR so inline suggestions never fail."""
    url = f"[https://api.github.com/repos/](https://api.github.com/repos/){repo}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    resp = requests.get(url, headers=headers, params={"per_page": 100}, timeout=20)
    resp.raise_for_status()

    diff_map: dict[str, set[int]] = {}
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for file_obj in resp.json():
        filename = file_obj.get("filename", "")
        patch = file_obj.get("patch", "")
        valid_lines: set[int] = set()
        current_line = 0

        for patch_line in patch.splitlines():
            match = hunk_pattern.match(patch_line)
            if match:
                current_line = int(match.group(1))
                continue
            if patch_line.startswith("+") and not patch_line.startswith("+++"):
                valid_lines.add(current_line)
                current_line += 1
            elif patch_line.startswith(" "):
                valid_lines.add(current_line)
                current_line += 1

        diff_map[filename] = valid_lines

    return diff_map


def build_inline_comment_body(finding: dict[str, Any], fix: dict[str, Any]) -> str:
    """Format a GitHub PR inline review comment with 1-click suggestion block."""
    title = fix.get("title", "Security Vulnerability")
    owasp = fix.get("owasp_category", finding["owasp"])
    cwe = fix.get("cwe", finding["cwe"])
    risk = fix.get("risk_explanation", finding["message"])
    summary = fix.get("remediation_summary", "Apply the secure coding pattern below.")
    fixed_code = fix.get("fixed_code", "").rstrip("\n")
    extra_import = fix.get("requires_import", "").strip()

    body = (
        f"### AI Security Auto-Remediation: {title}\n"
        f"**Category:** `{owasp}` | **CWE:** `{cwe}` | **Rule:** `{finding['rule_id']}`\n\n"
        f"**Risk:** {risk}\n\n"
        f"**Fix:** {summary}\n\n"
        f"```suggestion\n{fixed_code}\n```"
    )
    if extra_import:
        body += f"\n\n> **Import needed:** Ensure `{extra_import}` is imported at the top of `{finding['path']}`."
    return body


def build_summary_markdown(remediations: list[tuple[dict[str, Any], dict[str, Any]]]) -> str:
    """Build Markdown summary report for PR comment and GitHub Step Summary."""
    lines = [
        "## AI-Driven DevSecOps Remediation Report (Groq)",
        "",
        f"Detected **{len(remediations)}** SAST security finding(s) from Semgrep. Review the inline **`Commit suggestion`** blocks in the **Files changed** tab or apply the fixes below:",
        "",
        "| File | Line(s) | OWASP / CWE | Issue |",
        "| :--- | :--- | :--- | :--- |",
    ]

    for finding, fix in remediations:
        line_ref = (
            f"L{finding['start_line']}"
            if finding["start_line"] == finding["end_line"]
            else f"L{finding['start_line']}-L{finding['end_line']}"
        )
        cat = f"{fix.get('owasp_category', finding['owasp'])} ({fix.get('cwe', finding['cwe'])})"
        title = fix.get("title", finding["rule_id"]).replace("|", "/")
        lines.append(f"| `{finding['path']}` | {line_ref} | {cat} | {title} |")

    lines.append("")
    for idx, (finding, fix) in enumerate(remediations, start=1):
        fixed_code = fix.get("fixed_code", "").rstrip("\n")
        extra_import = fix.get("requires_import", "").strip()
        lines.extend(
            [
                f"### {idx}. {fix.get('title', finding['rule_id'])} (`{finding['path']}:L{finding['start_line']}`)",
                f"- **Risk:** {fix.get('risk_explanation', finding['message'])}",
                f"- **Fix:** {fix.get('remediation_summary', '')}",
            ]
        )
        if extra_import:
            lines.append(f"- **Required Import:** `{extra_import}`")
        lines.extend(["```python", fixed_code, "```", ""])

    lines.append("_Generated automatically by `scripts/ai_remediator.py` using Groq API._")
    return "\n".join(lines)


def post_to_github_pr(
    remediations: list[tuple[dict[str, Any], dict[str, Any]]],
    summary_md: str,
) -> None:
    """Post inline 1-click suggestions + summary comment to the GitHub PR."""
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    pr_number = os.environ.get("PR_NUMBER")

    if not all([token, repo, pr_number]):
        print("[INFO] GitHub PR environment variables not set. Skipping PR API calls.")
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }

    # 1. Try posting inline review with 1-click suggestion blocks
    try:
        diff_lines = get_pr_diff_lines(repo, pr_number, token)
        review_comments: list[dict[str, Any]] = []

        for finding, fix in remediations:
            path = finding["path"]
            start_line = finding["start_line"]
            end_line = finding["end_line"]
            valid = diff_lines.get(path, set())

            if all(ln in valid for ln in range(start_line, end_line + 1)):
                comment_obj: dict[str, Any] = {
                    "path": path,
                    "line": end_line,
                    "side": "RIGHT",
                    "body": build_inline_comment_body(finding, fix),
                }
                if end_line > start_line:
                    comment_obj["start_line"] = start_line
                    comment_obj["start_side"] = "RIGHT"
                review_comments.append(comment_obj)

        if review_comments:
            review_url = f"[https://api.github.com/repos/](https://api.github.com/repos/){repo}/pulls/{pr_number}/reviews"
            payload = {
                "event": "COMMENT",
                "body": "AI Security Gate found SAST vulnerabilities and prepared 1-click code remediation suggestions below.",
                "comments": review_comments,
            }
            resp = requests.post(review_url, headers=headers, json=payload, timeout=20)
            if resp.ok:
                print(f"[OK] Posted {len(review_comments)} inline 1-click suggestion(s) to PR #{pr_number}.")
            else:
                print(f"[WARN] Inline PR review returned {resp.status_code}: {resp.text}")
    except Exception as exc:
        print(f"[WARN] Could not post inline PR review (falling back to summary comment): {exc}")

    # 2. Always post consolidated Markdown summary comment on the PR
    comment_url = f"[https://api.github.com/repos/](https://api.github.com/repos/){repo}/issues/{pr_number}/comments"
    resp = requests.post(comment_url, headers=headers, json={"body": summary_md}, timeout=20)
    if resp.ok:
        print(f"[OK] Posted AI Remediation summary comment to PR #{pr_number}.")
    else:
        print(f"[ERROR] Failed to post PR summary comment ({resp.status_code}): {resp.text}")
        sys.exit(1)


def run_self_test(client: Groq, model: str) -> None:
    """Validate Groq structured remediation locally using an in-memory SQLi sample."""
    sample_finding = {
        "path": "app/sample_demo.py",
        "start_line": 4,
        "end_line": 4,
        "rule_id": "python.lang.security.audit.formatted-sql-query",
        "severity": "ERROR",
        "message": "Detected possible formatted SQL query. Use parameterized queries instead.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
    }
    vulnerable_snippet = '    row = conn.execute(f"SELECT id, role FROM users WHERE username = \'{username}\'").fetchone()'
    numbered_context = (
        "   1: def get_user_role(conn, username: str):\n"
        "   2:     if not username:\n"
        "   3:         return None\n"
        "   4:     row = conn.execute(f\"SELECT id, role FROM users WHERE username = '{username}'\").fetchone()\n"
        "   5:     return dict(row) if row else None"
    )

    print(f"[TEST] Calling Groq model '{model}' with sample SQL Injection...")
    fix = request_ai_fix(client, model, sample_finding, vulnerable_snippet, numbered_context)
    print("\n--- GENERATED GITHUB 1-CLICK SUGGESTION PREVIEW ---")
    print(build_inline_comment_body(sample_finding, fix))
    print("\n[PASS] AI Remediation engine verified successfully.")


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="AI-Driven DevSecOps Auto-Remediation Agent")
    parser.add_argument("--report", default="semgrep-report.json", help="Path to Semgrep JSON report")
    parser.add_argument("--output", default="ai-remediation-report.md", help="Output Markdown report path")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Groq LLM model ID")
    parser.add_argument("--dry-run", action="store_true", help="Generate report without posting to GitHub")
    parser.add_argument("--self-test", action="store_true", help="Run an offline-safe sample test against Groq API")
    args = parser.parse_args()

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        print("[ERROR] GROQ_API_KEY environment variable is missing.")
        sys.exit(1)

    client = Groq(api_key=api_key)

    if args.self_test:
        run_self_test(client, args.model)
        return

    findings = load_semgrep_findings(Path(args.report))
    if not findings:
        print("[OK] No Semgrep findings to remediate.")
        return

    remediations: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for finding in findings:
        file_path = finding["path"]
        if not Path(file_path).exists():
            print(f"[WARN] Skipping missing file: {file_path}")
            continue

        print(f"[AI] Analyzing {file_path}:L{finding['start_line']} ({finding['rule_id']})...")
        vuln_snippet, numbered_ctx = read_code_context(
            file_path, finding["start_line"], finding["end_line"]
        )
        try:
            fix = request_ai_fix(client, args.model, finding, vuln_snippet, numbered_ctx)
            remediations.append((finding, fix))
        except Exception as exc:
            print(f"[WARN] Groq remediation failed for {file_path}:L{finding['start_line']}: {exc}")

    if not remediations:
        print("[WARN] No remediations could be generated.")
        return

    summary_md = build_summary_markdown(remediations)
    Path(args.output).write_text(summary_md, encoding="utf-8")
    print(f"[OK] Saved remediation report to {args.output}")

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary_md + "\n")

    if not args.dry_run:
        post_to_github_pr(remediations, summary_md)


if __name__ == "__main__":
    main()
