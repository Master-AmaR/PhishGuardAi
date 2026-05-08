import base64
import hashlib
from urllib.parse import urlparse

import requests
from flask import current_app


class VirusTotalService:
    base_url = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key=None):
        self.api_key = api_key if api_key is not None else current_app.config.get("VIRUSTOTAL_API_KEY", "")

    @property
    def enabled(self):
        return bool(self.api_key)

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _normalize_url(self, target_url):
        parsed = urlparse(target_url)
        if parsed.scheme:
            return target_url
        return f"http://{target_url}"

    def _url_id(self, target_url):
        return base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")

    def _gui_url(self, target_url):
        url_hash = hashlib.sha256(target_url.encode()).hexdigest()
        return f"https://www.virustotal.com/gui/url/{url_hash}/detection"

    def scan_url(self, target_url):
        target_url = self._normalize_url(target_url)
        if not self.enabled:
            return self._offline_response(target_url)
        response = requests.post(
            f"{self.base_url}/urls",
            headers=self._headers(),
            data={"url": target_url},
            timeout=15,
        )
        response.raise_for_status()
        return response.json()

    def reputation_lookup(self, target_url):
        target_url = self._normalize_url(target_url)
        if not self.enabled:
            return self._offline_response(target_url)
        try:
            response = requests.get(
                f"{self.base_url}/urls/{self._url_id(target_url)}",
                headers=self._headers(),
                timeout=15,
            )
            if response.status_code == 404:
                submitted = self.scan_url(target_url)
                return self._submitted_response(submitted)
            response.raise_for_status()
            return self.parse_url_report(response.json(), target_url)
        except requests.RequestException as error:
            return self._error_response(error, target_url)

    def parse_url_report(self, payload, target_url):
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        return {
            "status": "Connected",
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total or 90,
            "detection_ratio": f"{malicious + suspicious}/{total or 90}",
            "reputation": payload.get("data", {}).get("attributes", {}).get("reputation", 0),
            "normalized_url": target_url,
            "gui_url": self._gui_url(target_url),
        }

    def _submitted_response(self, payload):
        analysis_id = payload.get("data", {}).get("id", "")
        target_url = payload.get("meta", {}).get("url_info", {}).get("url", "")
        target_url = self._normalize_url(target_url) if target_url else ""
        return {
            "status": "Submitted to VirusTotal",
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "detection_ratio": "Pending",
            "reputation": 0,
            "analysis_id": analysis_id,
            "normalized_url": target_url,
            "gui_url": self._gui_url(target_url) if target_url else "",
        }

    def _error_response(self, error, target_url):
        status_code = getattr(error.response, "status_code", None)
        status = f"VirusTotal error{f' {status_code}' if status_code else ''}"
        return {
            "status": status,
            "malicious": 0,
            "suspicious": 0,
            "total": 0,
            "detection_ratio": "Unavailable",
            "reputation": 0,
            "error": str(error),
            "normalized_url": target_url,
            "gui_url": self._gui_url(target_url),
        }

    def _offline_response(self, target_url=""):
        return {
            "status": "API key not configured",
            "malicious": 0,
            "suspicious": 0,
            "total": 90,
            "detection_ratio": "0/90",
            "reputation": 0,
            "normalized_url": self._normalize_url(target_url) if target_url else "",
            "gui_url": self._gui_url(self._normalize_url(target_url)) if target_url else "",
        }
