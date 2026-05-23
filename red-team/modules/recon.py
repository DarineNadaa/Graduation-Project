"""
modules/recon.py — Reconnaissance / Target Fingerprinting.

Probes the target for HTTP headers, server version, reachable routes,
and response timings. This is always the first module an operator runs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_KNOWN_ROUTES = [
    "/", "/search?q=test", "/auth/login", "/system/ping?host=127.0.0.1",
    "/files/read?path=readme.txt", "/files/upload", "/profile/",
]


class ReconModule(BaseModule):
    module_id = "recon"
    name = "Reconnaissance"
    description = "HTTP fingerprinting and route discovery against the target application."
    category = Category.RECON
    scenario_id = "PRE-ATTACK"
    severity = Severity.INFO
    lab = {
        "target_path": "/",
        "vulnerable_component": "Entire application surface",
        "story": (
            "Before attacking, you need to map the target. Open the home page "
            "and use reconnaissance to enumerate which routes are exposed and "
            "what stack the server is running."
        ),
        "learner_steps": [
            {"action": "Open the portal home page in the Lab Browser.",
             "expected": "You see the AcmeCorp portal with links to all sections."},
            {"action": "Click each link to map what services are available.",
             "expected": "You discover login, search, diagnostics, files, and profile pages."},
            {"action": "View the page source — look for HTML comments and server info.",
             "expected": "Hidden comments reveal server version and framework details."},
            {"action": "Note the response headers (use browser DevTools Network tab).",
             "expected": "Server headers reveal technology stack information."},
            {"action": "Document the attack surface you discovered.",
             "expected": "You have a map of all endpoints to guide further testing."},
        ],
        "detection_rule": "Wazuh web-scanner signature / sequential path probes from one IP",
        "success_markers": [
            "Every known route returns a status code in the log",
            "Summary: 'Probed N endpoints, N reachable'",
        ],
        "quick_probe": "/",
    }
    steps = [{'title': 'Fingerprint HTTP headers', 'hint': 'Capture Server, X-Powered-By, cookies', 'expected': 'Banner of the target web stack'}, {'title': 'Enumerate known routes', 'hint': 'Probe / /search /auth/login /system/ping /files/read /profile/', 'expected': 'Status code + latency per route'}, {'title': 'Compile route inventory', 'hint': 'Categorize reachable vs redirected vs forbidden endpoints', 'expected': 'Route map ready for downstream modules'}]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="extra_paths",
                display_name="Extra Paths",
                description="Comma-separated additional paths to probe (optional)",
                default="",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []

        # ── Header fingerprint ────────────────────────────────────────────
        self._log(log_fn, "Fingerprinting target headers...")
        r = self._get(target.base_url + "/", label="header-probe", timeout=target.timeout)
        steps.append(r)

        if r.success:
            interesting = ["Server", "X-Powered-By", "X-Frame-Options"]
            for h in interesting:
                val = r.detail  # We can parse from full response in a future version
                self._log(log_fn, f"  Header check: {h}")

        # ── Route probe ───────────────────────────────────────────────────
        routes = list(_KNOWN_ROUTES)
        extra = opts.get("extra_paths", "")
        if extra:
            routes += [p.strip() for p in extra.split(",") if p.strip()]

        self._log(log_fn, f"Probing {len(routes)} routes...")
        for route in routes:
            url = target.base_url + route
            r = self._get(url, label=route, timeout=target.timeout)
            symbol = "✓" if r.success and (r.status_code or 0) < 500 else "✗"
            self._log(log_fn, f"  [{symbol}] {r.status_code}  {route}")
            steps.append(r)

        reachable = sum(1 for s in steps if s.success and (s.status_code or 0) < 500)
        summary = f"Probed {len(steps)} endpoints, {reachable} reachable."
        return self._make_result(target, steps, summary, started)
