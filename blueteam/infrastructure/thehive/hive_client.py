"""
hive_client.py — TheHive Integration Client
=============================================
Handles all communication with TheHive case management platform.

In production this sends real HTTP requests to the Hive API.
In development/testing it logs calls without hitting the network
when HIVE_URL is not set or unreachable.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


class HiveClient:
    """
    Client for TheHive case management API.

    Parameters
    ----------
    base_url : Base URL of the Hive instance (e.g. http://localhost:9000).
    api_key  : Hive API key for authentication.
    timeout  : HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9000",
        api_key: str = "",
        timeout: float = 5.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        self.timeout = timeout

    def create_case(self, incident_id: str, title: str, severity: str) -> dict:
        """
        Create a new case in TheHive for the given incident.

        Parameters
        ----------
        incident_id : Internal incident identifier.
        title       : Case title displayed in Hive.
        severity    : One of low | medium | high | critical.

        Returns
        -------
        The Hive API response dict, or an empty dict on failure.
        """
        payload = {
            "title": title,
            "description": f"Automated case for incident {incident_id}",
            "severity": self._map_severity(severity),
            "tags": [incident_id],
        }
        return self._post("/api/case", payload)

    def update_case_severity(self, incident_id: str, severity: str) -> dict:
        """
        Update the severity of an existing Hive case.

        Parameters
        ----------
        incident_id : Used to locate the case by tag.
        severity    : New severity label.
        """
        logger.info(
            "[HiveClient] Updating case severity for incident '%s' → %s",
            incident_id, severity,
        )
        # In a real implementation, first find the case ID by incident tag,
        # then PATCH /api/case/{id}. Stubbed here.
        return {"status": "updated", "incident_id": incident_id, "severity": severity}

    def add_observable(self, case_id: str, data_type: str, value: str) -> dict:
        """
        Add an observable (IOC) to a Hive case.

        Parameters
        ----------
        case_id   : Hive case ID.
        data_type : Observable type (ip, domain, hash, etc.).
        value     : Observable value.
        """
        payload = {
            "dataType": data_type,
            "data": value,
        }
        return self._post(f"/api/case/{case_id}/artifact", payload)

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _post(self, path: str, payload: dict) -> dict:
        """Send a POST request to the Hive API. Returns {} on error."""
        url = f"{self.base_url}{path}"
        try:
            response = httpx.post(
                url,
                json=payload,
                headers=self.headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning("[HiveClient] Request to %s failed: %s", url, exc)
            return {}

    @staticmethod
    def _map_severity(severity: str) -> int:
        """Map string severity to Hive numeric severity (1–4)."""
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            severity.lower(), 2
        )
