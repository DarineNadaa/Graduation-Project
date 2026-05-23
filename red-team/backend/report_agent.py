"""
backend/report_agent.py — AI-augmented mission report generator.

The agent receives:
  • The learner's timeline (browser actions + terminal commands + lab events)
  • The variant they picked + its ideal_commands
  • Their progress result from lab_progress.compute()

It returns a structured coaching report:
  {
    grade, score, success, duration_seconds,
    summary,
    what_you_did_right: [{title, detail}],
    what_you_missed:    [{title, detail, how_to_fix}],
    ideal_approach:     [{step, title, command, why}],
    vulnerability_explained: {...},
    defensive_controls: [...],
    evidence_timeline:  [...],
    task_results:       [...],
    ai_coaching:        "free-form coaching paragraph from Ollama (or fallback)",
    ai_model:           "ollama/<model>" | "rule-based-fallback",
  }

Priority chain:
  1. Ollama (local Docker container — free, offline, no API key needed)
  2. Rules-based fallback (if Ollama container is not reachable)
"""
from __future__ import annotations
import json
import os
import time
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

# ── Vulnerability metadata per module (used by both AI + fallback path) ─────
VULN_INFO: Dict[str, Dict[str, Any]] = {
    "recon": {
        "name":              "Information Disclosure / Attack-Surface Exposure",
        "cvss_category":     "MEDIUM",
        "what_it_is":        "Public-facing pages leak internal route names, software versions, and developer comments that help an attacker plan deeper attacks.",
        "why_it_matters":    "Recon is the foundation of every breach. Hidden routes, commented-out dev paths, and verbose server banners shorten the time-to-exploit by hours.",
        "real_world_example":"The 2017 Equifax breach was preceded by Apache-Struts version disclosure on a forgotten endpoint.",
        "defenses": [
            {"control": "Strip developer comments at build", "implementation": "Use a minifier that removes <!-- … --> in production HTML."},
            {"control": "Remove server-version banners",    "implementation": "Set `ServerTokens Prod` (Apache) or `server_tokens off` (nginx)."},
            {"control": "Block directory enumeration",       "implementation": "Add a per-IP rate limit (10 req/s) on 404 paths."},
        ],
    },
    "brute_force": {
        "name":              "Authentication — No Rate Limit / No Lockout",
        "cvss_category":     "HIGH",
        "what_it_is":        "The login endpoint accepts unlimited password attempts without throttling or account lockout, and leaks whether a username exists.",
        "why_it_matters":    "Attackers can spray common passwords across many accounts or hammer one account with a leaked password list — a billion logins cost ~$5 in cloud compute today.",
        "real_world_example":"In 2019 a credential-stuffing attack on Dunkin' Donuts compromised tens of thousands of accounts that reused leaked passwords.",
        "defenses": [
            {"control": "Per-account rate limit",  "implementation": "Use Redis to track failed-attempt counts per username — lock for 15 min after 5 failures."},
            {"control": "Per-IP rate limit",       "implementation": "Add a sliding-window limiter (10 req/min) on /auth/login."},
            {"control": "Identical error messages","implementation": "Always return `Invalid credentials` — never reveal whether the username exists."},
            {"control": "MFA",                     "implementation": "Require a second factor (TOTP, WebAuthn) for any admin account."},
        ],
    },
    "xss": {
        "name":              "Reflected Cross-Site Scripting (XSS)",
        "cvss_category":     "HIGH",
        "what_it_is":        "User input is rendered into the HTML response without escaping. An attacker can inject `<script>` or event-handler payloads that run in another user's browser.",
        "why_it_matters":    "XSS leads to session theft, credential phishing, and full account takeover. It bypasses HTTPS — the browser executes the script with the victim's full privileges.",
        "real_world_example":"In 2018 British Airways suffered an XSS-based card-skimmer (Magecart) that stole 380,000 customers' payment data.",
        "defenses": [
            {"control": "Context-aware output encoding", "implementation": "Use a templating engine with autoescape ON. Never use |safe / `dangerouslySetInnerHTML` for user input."},
            {"control": "Content Security Policy",       "implementation": "Set CSP `script-src 'self'; object-src 'none'; base-uri 'self'` and never `'unsafe-inline'`."},
            {"control": "HttpOnly + Secure cookies",     "implementation": "Mark session cookies HttpOnly so XSS can't read them; Secure so they only travel over HTTPS."},
        ],
    },
    "cmd_injection": {
        "name":              "OS Command Injection",
        "cvss_category":     "CRITICAL",
        "what_it_is":        "User input is concatenated into a shell command. Shell metacharacters (`;`, `|`, `$()`, backticks) inject and run arbitrary commands on the server.",
        "why_it_matters":    "Command injection means full remote code execution — the attacker runs as the app's UID and can read secrets, pivot to other hosts, and install backdoors.",
        "real_world_example":"In 2019 a single command-injection bug in a Citrix appliance (CVE-2019-19781) led to network breaches at the U.S. Census Bureau and multiple Fortune 500 companies.",
        "defenses": [
            {"control": "Use parameterized APIs",       "implementation": "Replace shell calls with `subprocess.run(['/bin/ping', '-c', '2', host], shell=False)` — the array form, not a string."},
            {"control": "Strict input validation",      "implementation": "Allow only `[a-zA-Z0-9.-]` for hostnames; reject everything else."},
            {"control": "Run with minimum privileges",  "implementation": "App should run as a non-root user with no shell, in a read-only filesystem with no /etc/passwd to leak."},
        ],
    },
    "dir_traversal": {
        "name":              "Path Traversal",
        "cvss_category":     "HIGH",
        "what_it_is":        "A `path` parameter is concatenated to a base directory without normalization. `../` sequences escape the intended directory and disclose arbitrary files.",
        "why_it_matters":    "Path traversal leaks /etc/passwd, SSH keys, .env files, application source code, and database credentials. It's often the first step before full RCE.",
        "real_world_example":"In 2021 a Microsoft Exchange traversal bug (CVE-2021-26858) was used in the HAFNIUM attacks against 250,000+ servers worldwide.",
        "defenses": [
            {"control": "Canonicalize paths",          "implementation": "Resolve `os.path.realpath(base + path)` and verify it `startswith(base)` before opening the file."},
            {"control": "Allowlist filenames",         "implementation": "Maintain a list of allowed document IDs; never accept a free-form path from the client."},
            {"control": "Serve files via signed URLs", "implementation": "Generate time-limited S3-style URLs so the app never reads the filesystem from a user-supplied path."},
        ],
    },
    "file_upload": {
        "name":              "Unrestricted Dangerous File Upload",
        "cvss_category":     "HIGH",
        "what_it_is":        "The upload endpoint accepts any filename and any content. Dangerous extensions (.php, .jsp, .sh) are stored unchanged.",
        "why_it_matters":    "If the storage directory is served by the application server, an uploaded file becomes executable — instant RCE. Even when files are static, they can host phishing pages, malware, or stored XSS.",
        "real_world_example":"The 2019 Magento commerce breach used an unrestricted upload bug to plant card-skimming JavaScript across thousands of merchant sites.",
        "defenses": [
            {"control": "Validate content, not filename","implementation": "Use libmagic / mimetypes to verify the real file type — reject anything outside an explicit allowlist (jpg, png, pdf)."},
            {"control": "Rename uploads on save",        "implementation": "Use a UUID + the validated extension. Never trust the user-supplied filename."},
            {"control": "Serve uploads from a separate domain","implementation": "Put `static-uploads.example.com` on a domain WITHOUT any script-execution handlers."},
        ],
    },
    "csrf": {
        "name":              "Cross-Site Request Forgery",
        "cvss_category":     "MEDIUM",
        "what_it_is":        "State-changing endpoints accept POSTs without verifying the request's origin. An attacker can trick a logged-in victim into submitting a malicious form from a third-party site.",
        "why_it_matters":    "CSRF lets the attacker perform any action as the victim — change email, transfer funds, escalate privileges — without ever stealing credentials.",
        "real_world_example":"In 2008 a CSRF flaw in YouTube allowed attackers to add videos to anyone's favorites and subscribe them to channels.",
        "defenses": [
            {"control": "CSRF tokens on every state-changing form","implementation": "Hidden token signed with the session; server rejects POSTs missing/wrong token."},
            {"control": "SameSite=Strict cookies",                 "implementation": "Cookies marked SameSite=Strict are not sent on cross-site requests at all."},
            {"control": "Origin/Referer header check",             "implementation": "On every POST, verify `Origin == https://yourapp` before accepting."},
        ],
    },
}


def _gather_evidence_text(progress: dict, timeline: list) -> str:
    """Build a compact textual summary the LLM can read."""
    lines: List[str] = []
    if progress.get("variant_name"):
        lines.append(f"Variant chosen: {progress['variant_name']}")
    lines.append(f"Progress: {progress.get('progress_percent', 0)}% — "
                 f"success={progress.get('success', False)}")
    lines.append(f"Tasks ({len(progress.get('tasks', []))}):")
    for i, t in enumerate(progress.get("tasks", [])):
        mark = "✓" if t.get("complete") else "✗"
        lines.append(f"  {mark} {i+1}. {t['title']}  ({t.get('match_count',0)}/{t.get('min_count',1)})")
    lines.append("Timeline (first 40 events):")
    for x in timeline[:40]:
        ts = x.get("ts", 0.0)
        lines.append(f"  [{x.get('channel','?'):<8}] {x.get('kind','?'):<22} — {(x.get('summary') or '')[:120]}")
    if len(timeline) > 40:
        lines.append(f"  … (+{len(timeline)-40} more)")
    return "\n".join(lines)


def _ai_coach(progress: dict, variant: dict, timeline: list, vuln: dict) -> Dict[str, Any]:
    """Skip Ollama — return rule-based coaching immediately."""
    return {"coaching": None, "model": "rule-based-fallback"}


def _rule_based_coaching(progress: dict, vuln: dict) -> str:
    """Fallback prose when no API key is available."""
    pct = progress.get("progress_percent", 0)
    if progress.get("success"):
        opening = (
            f"You demonstrated {vuln.get('name')} successfully with a {pct}% task-completion score. "
            f"The right evidence fired in the right order, and the success criteria all hit. "
            f"That tells me you understood the mechanic, not just the syntax."
        )
        followup = (
            "The most valuable next step is to revisit the harder variant of this module — "
            "the same vulnerability under a tougher filter. Reading the ideal-approach commands "
            "below side-by-side with your own attempts will sharpen your intuition for which "
            "bypasses work in production environments."
        )
    elif pct >= 50:
        opening = (
            f"You hit {pct}% of the task ladder. You correctly probed the endpoint and started "
            f"forming payloads, which is the right shape for {vuln.get('name')}. "
            f"What kept you from finishing was the final confirmation step."
        )
        followup = (
            "Look at the 'Ideal Approach' commands below. The last 1-2 steps usually need a "
            "specific success indicator (a 302 redirect, a 'uid=' string, an unescaped tag). "
            "Re-run the attack and grep for that indicator explicitly."
        )
    else:
        opening = (
            f"You touched the target but didn't yet trigger the success criteria for {vuln.get('name')}. "
            f"The attack chain is straightforward once you see it, but missing any one step means "
            f"the evidence engine doesn't credit your progress."
        )
        followup = (
            "Read the 'Ideal Approach' commands below and run them one at a time, watching what "
            "each one returns. The lab tells you exactly what success looks like — when you see "
            "those indicators in your output, you've found the bug."
        )
    return opening + "\n\n" + followup


def _grade(progress: dict, browser_vs_attackbox: tuple) -> tuple:
    """Return (grade_letter, score 0-100)."""
    score = 0.0
    if progress.get("success"):
        score += 40
    tasks = progress.get("tasks", [])
    if tasks:
        done = len(progress.get("completed_tasks", []))
        score += (done / len(tasks)) * 40
    ev_count = len(progress.get("evidence", []))
    score += min(ev_count / 10.0, 1.0) * 20

    # Penalty: operator mode but more browser events than attackbox events
    browser_n, attackbox_n = browser_vs_attackbox
    if browser_n > attackbox_n > 0:
        score -= 10

    score = max(0, min(100, int(round(score))))
    if score >= 90 and progress.get("success"): grade = "S"
    elif score >= 75 and progress.get("success"): grade = "A"
    elif score >= 55 and progress.get("success"): grade = "B"
    elif score >= 30: grade = "C"
    else: grade = "F"
    return grade, score


def generate(session, events: list, timeline: list,
             progress: dict, mode: str = "tutorial") -> Dict[str, Any]:
    """Produce the full structured report."""
    module_id  = getattr(session.module, "module_id", None) or getattr(session, "module_id", None)
    module_name = getattr(session.module, "name", None) or module_id
    variant_id = getattr(session, "variant_id", None) or progress.get("variant_id")

    # Look up variant — best effort
    try:
        from backend import lab_progress
        variant = lab_progress.get_variant_spec(module_id, variant_id) or {}
    except Exception:
        variant = {}

    vuln = VULN_INFO.get(module_id, {
        "name":              module_id or "Unknown",
        "cvss_category":     "INFO",
        "what_it_is":        "—",
        "why_it_matters":    "—",
        "real_world_example":"—",
        "defenses":          [],
    })

    # Browser vs AttackBox event count for grading penalty
    browser_n   = sum(1 for e in events if e.get("via") == "browser")
    attackbox_n = sum(1 for e in events if e.get("via") == "attackbox")

    # Score & grade
    grade, score = _grade(progress, (browser_n, attackbox_n))

    # Task results with feedback strings
    task_results: List[Dict[str, Any]] = []
    for t in progress.get("tasks", []):
        ok = bool(t.get("complete"))
        fb = ("Well done — this step's evidence fired as expected."
              if ok else
              f"Missed — needed {t.get('min_count',1)} matching event(s), saw {t.get('match_count',0)}.")
        task_results.append({
            "title":          t.get("title"),
            "completed":      ok,
            "evidence_count": t.get("match_count", 0),
            "min_count":      t.get("min_count", 1),
            "feedback":       fb,
        })

    # Specific "did right" / "missed" lines
    did_right: List[Dict[str, str]] = []
    missed:    List[Dict[str, str]] = []
    for t in task_results:
        if t["completed"]:
            did_right.append({
                "title":  t["title"],
                "detail": f"Completed with {t['evidence_count']} supporting event(s).",
            })
        else:
            missed.append({
                "title":      t["title"],
                "detail":     f"Required {t['min_count']} event(s) — observed {t['evidence_count']}.",
                "how_to_fix": "Follow the ideal-approach command below for this step.",
            })

    if not missed and progress.get("success"):
        did_right.append({
            "title":  "Clean execution",
            "detail": "Every required success event fired. The vulnerability was conclusively demonstrated.",
        })

    # Ideal approach — from the variant's ideal_commands
    ideal_approach: List[Dict[str, Any]] = []
    cmds = variant.get("ideal_commands", [])
    for i, cmd in enumerate(cmds, start=1):
        ideal_approach.append({
            "step":    i,
            "title":   f"Step {i}",
            "command": cmd,
            "why":     "" if cmd.startswith("#") else "Execute and observe the response.",
        })

    # Defensive controls
    defensive = [{"control": d["control"], "implementation": d["implementation"]}
                 for d in vuln.get("defenses", [])]

    # Evidence timeline (chronological)
    started_at = session.mission_started_at or 0.0
    ev_timeline: List[Dict[str, Any]] = []
    for x in timeline:
        ev_timeline.append({
            "timestamp":   x.get("ts", 0.0),
            "delta_s":     round((x.get("ts", 0.0) - started_at), 2) if started_at else None,
            "channel":     x.get("channel", "?"),
            "kind":        x.get("kind", "?"),
            "description": x.get("summary", ""),
        })

    duration = None
    if progress.get("evidence"):
        last_ts = max((e.get("timestamp") or 0.0) for e in progress["evidence"])
        if last_ts and started_at:
            duration = int(round(last_ts - started_at))

    # AI coaching — Claude or fallback
    coach = _ai_coach(progress, variant, timeline, vuln)
    if not coach.get("coaching"):
        coach["coaching"] = _rule_based_coaching(progress, vuln)

    summary = (
        f"Variant '{progress.get('variant_name') or variant_id or 'default'}' attempted in "
        f"{mode} mode. {progress.get('progress_percent', 0)}% of the task ladder completed. "
        f"{('Success criteria met.' if progress.get('success') else 'Success criteria NOT met yet.')}"
    )

    return {
        "session_id":   session.session_id,
        "module_id":    module_id,
        "module_name":  module_name,
        "generated_at": time.time(),
        "mode":         mode,
        "variant_id":   variant_id,
        "variant_name": variant.get("name") or progress.get("variant_name"),
        "grade":        grade,
        "score":        score,
        "duration_seconds": duration,
        "success":      bool(progress.get("success")),

        "summary":            summary,
        "ai_coaching":        coach["coaching"],
        "ai_model":           coach["model"],

        "what_you_did_right": did_right,
        "what_you_missed":    missed,
        "ideal_approach":     ideal_approach,
        "vulnerability_explained": {
            "name":              vuln.get("name"),
            "cvss_category":     vuln.get("cvss_category"),
            "what_it_is":        vuln.get("what_it_is"),
            "why_it_matters":    vuln.get("why_it_matters"),
            "real_world_example":vuln.get("real_world_example"),
        },
        "defensive_controls": defensive,
        "evidence_timeline":  ev_timeline,
        "task_results":       task_results,

        "channel_breakdown": {
            "browser":   browser_n,
            "attackbox": attackbox_n,
        },
    }
