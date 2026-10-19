"""JSON-Lines file event transport for local log shipping and offline testing."""

from collections.abc import Sequence
from pathlib import Path
import threading

from trojan_defense.core.exceptions import TransportError
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.transport.base import BaseEventTransport


class JsonLineFileTransport(BaseEventTransport):
    """Transports events by appending JSON lines to a designated local file."""

    def __init__(self, file_path: str | Path = "events.jsonl") -> None:
        self.file_path = Path(file_path)
        self._lock = threading.Lock()
        self.is_closed = False

        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.file_path, "a", encoding="utf-8")
        except OSError as exc:
            raise TransportError(f"Failed to open transport file '{self.file_path}': {exc}") from exc

    def send(self, event: SecurityEvent) -> bool:
        with self._lock:
            if self.is_closed:
                raise TransportError("Cannot send event via closed transport")
            try:
                line = event.to_json() + "\n"
                self._file.write(line)
                self._file.flush()
                return True
            except OSError as exc:
                raise TransportError(f"Failed to write event to '{self.file_path}': {exc}") from exc

    def send_batch(self, events: Sequence[SecurityEvent]) -> int:
        with self._lock:
            if self.is_closed:
                raise TransportError("Cannot send batch via closed transport")
            try:
                count = 0
                for event in events:
                    line = event.to_json() + "\n"
                    self._file.write(line)
                    count += 1
                self._file.flush()
                return count
            except OSError as exc:
                raise TransportError(f"Failed to write batch to '{self.file_path}': {exc}") from exc

    def close(self) -> None:
        with self._lock:
            if not self.is_closed:
                self.is_closed = True
                try:
                    self._file.close()
                except OSError:
                    pass
