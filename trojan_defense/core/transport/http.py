"""HTTP event transport for streaming events to the backend ingestion endpoint.

Uses Python standard library urllib.request to dispatch SecurityEvents to
POST /api/events with deterministic error propagation and duplicate awareness.
"""

from collections.abc import Sequence
import json
import logging
import urllib.error
import urllib.request

from trojan_defense.core.exceptions import TransportError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.transport.base import BaseEventTransport

logger = get_logger("transport.http")


class HttpEventTransport(BaseEventTransport):
    """Dispatches SecurityEvents to a remote or local HTTP ingestion endpoint."""

    def __init__(
        self,
        endpoint_url: str = "http://127.0.0.1:8080/api/events",
        timeout: float = 5.0,
        retries: int = 1,
    ) -> None:
        self.endpoint_url = endpoint_url.strip()
        self.timeout = timeout
        self.retries = max(0, retries)
        self.is_closed = False

    def send(self, event: SecurityEvent) -> bool:
        """Transmit a single event to the HTTP backend.

        Raises:
            TransportError: If backend is unreachable or returns an unrecoverable error.
        """
        if self.is_closed:
            raise TransportError("Cannot send event via closed HTTP transport")

        payload = event.to_json().encode("utf-8")
        req = urllib.request.Request(
            self.endpoint_url,
            data=payload,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(payload)),
            },
            method="POST",
        )

        attempts = 0
        last_error: Exception | None = None

        while attempts <= self.retries:
            attempts += 1
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    status_code = response.getcode()
                    if status_code in (200, 201):
                        return True
                    # Unexpected success code
                    return True
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    # Duplicate event detected by backend
                    logger.info(
                        f"Backend reported duplicate event '{event.event_id}', preserved original"
                    )
                    return True
                error_body = exc.read().decode("utf-8", errors="replace")
                logger.error(f"HTTP error {exc.code} from backend: {error_body}")
                raise TransportError(f"HTTP error {exc.code}: {error_body}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                logger.warning(
                    f"Attempt {attempts}/{self.retries + 1} failed reaching {self.endpoint_url}: {exc}"
                )

        raise TransportError(
            f"Failed to transmit event to backend at '{self.endpoint_url}': {last_error}"
        ) from last_error

    def send_batch(self, events: Sequence[SecurityEvent]) -> int:
        """Transmit a batch of events to the backend.

        Dispatches to the batch endpoint if available, or falls back to individual sends.
        """
        if self.is_closed:
            raise TransportError("Cannot send batch via closed HTTP transport")
        if not events:
            return 0

        # Attempt batch endpoint if URL ends with /api/events
        batch_url = (
            f"{self.endpoint_url}/batch"
            if not self.endpoint_url.endswith("/batch")
            else self.endpoint_url
        )
        payload = json.dumps({"events": [e.to_dict() for e in events]}).encode("utf-8")
        req = urllib.request.Request(
            batch_url,
            data=payload,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(payload)),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.getcode() in (200, 201):
                    return len(events)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Batch endpoint not supported at this exact URL, fall back to sequential send
                pass
            else:
                error_body = exc.read().decode("utf-8", errors="replace")
                raise TransportError(f"Batch HTTP error {exc.code}: {error_body}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"Backend unreachable for batch transmission: {exc}") from exc

        # Sequential fallback
        sent = 0
        for ev in events:
            if self.send(ev):
                sent += 1
        return sent

    def close(self) -> None:
        self.is_closed = True
