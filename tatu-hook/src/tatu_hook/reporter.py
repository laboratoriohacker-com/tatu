"""Async event reporter — fire-and-forget POST to Tatu API."""
from __future__ import annotations

import json
import threading
import urllib.request
import urllib.error

_pending_threads: list[threading.Thread] = []


def report_event(api_url: str, api_key: str, event: dict) -> None:
    """Fire-and-forget event report in a background thread."""
    if not api_url or not api_key:
        return

    def _send():
        try:
            url = f"{api_url}/api/v1/events"
            body = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json", "X-API-Key": api_key},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except (urllib.error.URLError, OSError):
            pass  # fire-and-forget

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()
    _pending_threads.append(thread)


def flush(timeout: float = 5.0) -> None:
    """Wait for all pending report threads to finish before exit."""
    for thread in _pending_threads:
        thread.join(timeout=timeout)
    _pending_threads.clear()
