"""HTTP REST API server for backend event ingestion and querying.

Uses standard library http.server.ThreadingHTTPServer with zero external dependencies.
Provides structured request handling, strict validation, bounded pagination,
deterministic deduplication responses, and input size protections.
"""

from datetime import datetime, timezone
from http import HTTPStatus
import http.server
import mimetypes
from pathlib import Path
import json
import socket
import threading
from typing import Any
import urllib.parse
import uuid

from trojan_defense.alerting.repository import AlertQueryFilter
from trojan_defense.backend.service import EventService
from trojan_defense.core.config.schema import BackendConfig
from trojan_defense.core.exceptions import PersistenceError, ValidationError
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.event import current_utc_timestamp
from trojan_defense.core.persistence.base import EventQueryFilter
from trojan_defense.response.auth import (
    AuthorizationError,
    Permission,
    Role,
    UserContext,
    resolve_user_context,
)
from trojan_defense.response.models import (
    ActionStatus,
    IncidentStatus,
    ResponseActionType,
    normalize_response_action_type,
)

logger = get_logger("backend.server")


class EventIngestionHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for event ingestion, querying, and health status."""

    server: "BackendHTTPServer"  # Type hint for custom server attribute

    def log_message(self, format: str, *args: Any) -> None:
        """Forward HTTP server logs to structured logger instead of stderr."""
        logger.debug(f"{self.address_string()} - {format % args}")

    def _send_json_response(self, status: int, data: dict[str, Any]) -> None:
        """Serialize data to JSON and send response with appropriate headers."""
        try:
            body = json.dumps(data, indent=2).encode("utf-8")
        except Exception as exc:
            logger.error(f"Failed to serialize response: {exc}")
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'{"error": "Internal serialization error"}')
            return

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, Any] | list[Any] | None:
        """Read and parse JSON request body with size protection."""
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing Content-Length header"},
            )
            return None

        try:
            content_length = int(content_length_header)
        except ValueError:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid Content-Length header"},
            )
            return None

        max_limit = self.server.config.max_content_length
        if content_length > max_limit:
            logger.warning(f"Request body size {content_length} exceeds limit {max_limit}")
            try:
                self.rfile.read(content_length)
            except Exception:
                pass
            self._send_json_response(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "error": "Payload Too Large",
                    "content_length": content_length,
                    "max_allowed": max_limit,
                },
            )
            return None

        raw_data = self.rfile.read(content_length)
        try:
            return json.loads(raw_data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Malformed JSON payload", "details": str(exc)},
            )
            return None

    def _read_optional_json_body(self) -> dict[str, Any]:
        """Read and parse optional JSON request body, returning empty dict if missing."""
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            return {}
        try:
            content_length = int(content_length_header)
            if content_length <= 0:
                return {}
        except ValueError:
            return {}

        max_limit = self.server.config.max_content_length
        if content_length > max_limit:
            return {}

        raw_data = self.rfile.read(content_length)
        if not raw_data.strip():
            return {}
        try:
            data = json.loads(raw_data.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _get_user_context(self) -> UserContext:
        """Extract UserContext from request headers or default tokens."""
        auth_header = self.headers.get("Authorization")
        api_key_header = self.headers.get("X-API-Key")
        role_header = self.headers.get("X-User-Role")
        actor_header = self.headers.get("X-Actor")

        token = auth_header or api_key_header
        auth_tokens = getattr(self.server, "auth_tokens", {})

        return resolve_user_context(
            token=token,
            role_header=role_header,
            actor_header=actor_header,
            configured_tokens=auth_tokens,
            default_role=Role.ADMIN,
        )

    def _serve_static_file(self, relative_path: str) -> None:
        """Serve a dashboard asset from the project root with path traversal protection."""
        try:
            root = Path(__file__).resolve().parents[2]
            requested = (root / relative_path).resolve()
            if root not in requested.parents and requested != root:
                self.send_error(HTTPStatus.FORBIDDEN)
                return
            if not requested.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            data = requested.read_bytes()
            content_type = mimetypes.guess_type(str(requested))[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except OSError as exc:
            logger.error(f"Static file error: {exc}")
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_GET(self) -> None:
        """Handle GET requests for health status, event querying, alerts, incidents, responses, and audit logs."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Dashboard/static assets are served by the same backend origin.
        # This keeps the project self-contained and avoids CORS setup for the UI.
        if path in ("", "/"):
            self._serve_static_file("web/index.html")
            return
        if path.startswith("/web/"):
            self._serve_static_file(path.lstrip("/"))
            return

        # Route: GET /api/health
        if path in ("/api/health", "/health"):
            self._handle_health()
            return

        # Route: GET /api/alerts/<alert_id>/evidence
        if path.startswith("/api/alerts/") and path.endswith("/evidence"):
            alert_id = path[len("/api/alerts/") : -len("/evidence")].rstrip("/")
            self._handle_get_alert_evidence(alert_id)
            return

        # Route: GET /api/alerts/<alert_id>/recommendations
        if path.startswith("/api/alerts/") and path.endswith("/recommendations"):
            alert_id = path[len("/api/alerts/") : -len("/recommendations")].rstrip("/")
            self._handle_get_alert_recommendations(alert_id)
            return

        # Route: GET /api/alerts/<alert_id>
        if path.startswith("/api/alerts/"):
            alert_id = path[len("/api/alerts/") :]
            self._handle_get_single_alert(alert_id)
            return

        # Route: GET /api/alerts
        if path == "/api/alerts":
            self._handle_query_alerts(query_params)
            return

        # Route: GET /api/events
        if path == "/api/events":
            self._handle_query_events(query_params)
            return

        # Route: GET /api/events/<event_id>
        if path.startswith("/api/events/"):
            event_id = path[len("/api/events/") :]
            self._handle_get_single_event(event_id)
            return

        # Route: GET /api/incidents/<incident_id>
        if path.startswith("/api/incidents/"):
            incident_id = path[len("/api/incidents/") :]
            self._handle_get_single_incident(incident_id)
            return

        # Route: GET /api/incidents
        if path == "/api/incidents":
            self._handle_list_incidents(query_params)
            return

        # Route: GET /api/responses/<action_id>
        if path.startswith("/api/responses/"):
            action_id = path[len("/api/responses/") :]
            self._handle_get_single_response(action_id)
            return

        # Route: GET /api/responses
        if path == "/api/responses":
            self._handle_list_responses(query_params)
            return

        # Route: GET /api/audit/<audit_id>
        if path.startswith("/api/audit/"):
            audit_id = path[len("/api/audit/") :]
            self._handle_get_single_audit(audit_id)
            return

        # Route: GET /api/audit
        if path == "/api/audit":
            self._handle_list_audit(query_params)
            return

        self._send_json_response(
            HTTPStatus.NOT_FOUND,
            {"error": "Endpoint not found", "path": self.path},
        )

    def do_POST(self) -> None:
        """Handle POST requests for events, alerts, incidents, and responses."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path.rstrip("/")

        # Route: POST /api/alerts/<alert_id>/acknowledge
        if path.startswith("/api/alerts/") and path.endswith("/acknowledge"):
            alert_id = path[len("/api/alerts/") : -len("/acknowledge")].rstrip("/")
            self._handle_acknowledge_alert(alert_id)
            return

        # Route: POST /api/alerts/<alert_id>/resolve
        if path.startswith("/api/alerts/") and path.endswith("/resolve"):
            alert_id = path[len("/api/alerts/") : -len("/resolve")].rstrip("/")
            self._handle_resolve_alert(alert_id)
            return

        # Route: POST /api/alerts/<alert_id>/status
        if path.startswith("/api/alerts/") and path.endswith("/status"):
            alert_id = path[len("/api/alerts/") : -len("/status")].rstrip("/")
            self._handle_update_alert_status(alert_id)
            return

        # Route: POST /api/demo/test-detection
        # Generates a fresh server-side UUID so repeated dashboard demo clicks
        # can never reuse a stale event ID from the browser.
        if path == "/api/demo/test-detection":
            self._handle_demo_test_detection()
            return

        # Route: POST /api/events
        if path == "/api/events":
            self._handle_ingest_event()
            return

        # Route: POST /api/events/batch
        if path == "/api/events/batch":
            self._handle_ingest_batch()
            return

        # Route: POST /api/incidents/<incident_id>/status
        if path.startswith("/api/incidents/") and path.endswith("/status"):
            incident_id = path[len("/api/incidents/") : -len("/status")].rstrip("/")
            self._handle_update_incident_status(incident_id)
            return

        # Route: POST /api/incidents/<incident_id>/notes
        if path.startswith("/api/incidents/") and path.endswith("/notes"):
            incident_id = path[len("/api/incidents/") : -len("/notes")].rstrip("/")
            self._handle_add_incident_note(incident_id)
            return

        # Route: POST /api/incidents/<incident_id>/alerts
        if path.startswith("/api/incidents/") and path.endswith("/alerts"):
            incident_id = path[len("/api/incidents/") : -len("/alerts")].rstrip("/")
            self._handle_associate_incident_alert(incident_id)
            return

        # Route: POST /api/incidents
        if path == "/api/incidents":
            self._handle_create_incident()
            return

        # Route: POST /api/responses/<action_id>/authorize
        if path.startswith("/api/responses/") and path.endswith("/authorize"):
            action_id = path[len("/api/responses/") : -len("/authorize")].rstrip("/")
            self._handle_authorize_response_action(action_id)
            return

        # Route: POST /api/responses/<action_id>/reject
        if path.startswith("/api/responses/") and path.endswith("/reject"):
            action_id = path[len("/api/responses/") : -len("/reject")].rstrip("/")
            self._handle_reject_response_action(action_id)
            return

        # Route: POST /api/responses/<action_id>/execute
        if path.startswith("/api/responses/") and path.endswith("/execute"):
            action_id = path[len("/api/responses/") : -len("/execute")].rstrip("/")
            self._handle_execute_response_action(action_id)
            return

        # Route: POST /api/responses/<action_id>/rollback
        if path.startswith("/api/responses/") and path.endswith("/rollback"):
            action_id = path[len("/api/responses/") : -len("/rollback")].rstrip("/")
            self._handle_rollback_response_action(action_id)
            return

        # Route: POST /api/responses
        if path == "/api/responses":
            self._handle_request_response_action()
            return

        self._send_json_response(
            HTTPStatus.NOT_FOUND,
            {"error": "Endpoint not found", "path": self.path},
        )

    def _handle_health(self) -> None:
        """Return backend health and readiness status."""
        data = {
            "status": "healthy",
            "service": "trojan-defense-backend",
            "version": "0.1.0",
            "timestamp": current_utc_timestamp(),
            "total_events": self.server.service.count(),
            "total_alerts": self.server.service.count_alerts(),
            "total_incidents": self.server.service.count_incidents(),
            "total_responses": self.server.service.count_response_actions(),
        }
        self._send_json_response(HTTPStatus.OK, data)

    def _handle_demo_test_detection(self) -> None:
        """Create one fresh demo behavioral/deception event for the SOC dashboard."""
        event_id = str(uuid.uuid4())
        timestamp = current_utc_timestamp()
        payload = {
            "event_id": event_id,
            "schema_version": "1.0.0",
            "timestamp": timestamp,
            "event_type": "BEHAVIOR.FINDING",
            "severity": "HIGH",
            "source": "dashboard.demo.deception",
            "endpoint": {
                "endpoint_id": "dashboard-demo",
                "hostname": "DEMO-ENDPOINT",
                "platform": "Windows",
                "os_version": "demo",
                "architecture": "x64",
                "agent_version": "0.1.0",
            },
            "context": {
                "process": {
                    "pid": 4242,
                    "name": "suspicious_demo_process",
                    "executable_path": "C:\\Demo\\suspicious_demo_process.exe",
                    "command_line": "suspicious_demo_process --deception-test",
                },
                "behavior": {
                    "finding_id": event_id,
                    "rule_id": "RULE-BEH-005",
                    "rule_name": "Cyber deception decoy interaction",
                    "description": "Demo interaction with a monitored deception asset.",
                    "matched_conditions": ["decoy_interaction", "dashboard_test"],
                    "confidence": 1.0,
                    "related_event_ids": [event_id],
                    "evidence": [{
                        "category": "DECEPTION",
                        "is_decoy": True,
                        "decoy_id": "dashboard-demo-decoy",
                        "interaction_type": "READ",
                        "event_id": event_id,
                    }],
                },
                "deception": {
                    "is_decoy": True,
                    "decoy_id": "dashboard-demo-decoy",
                    "decoy_type": "FILE",
                    "interaction_type": "READ",
                    "path": "runtime/deception/demo_confidential.txt",
                    "action": "READ",
                    "status": "TRIGGERED",
                },
            },
        }

        try:
            event, is_new = self.server.service.ingest_event(payload)
            if not is_new:
                # Extremely defensive fallback: regenerate once if a collision ever occurs.
                payload["event_id"] = str(uuid.uuid4())
                payload["context"]["behavior"]["finding_id"] = payload["event_id"]
                payload["context"]["behavior"]["related_event_ids"] = [payload["event_id"]]
                payload["context"]["behavior"]["evidence"][0]["event_id"] = payload["event_id"]
                event, is_new = self.server.service.ingest_event(payload)

            alert = None
            alert_engine = getattr(self.server.service, "alert_engine", None)
            if is_new and alert_engine is not None:
                try:
                    alert = alert_engine.process_finding_event(event)
                except Exception as exc:
                    logger.warning("Demo event stored but alert generation failed: %s", exc, exc_info=True)

            self._send_json_response(
                HTTPStatus.CREATED,
                {
                    "status": "created",
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "alert": alert.to_dict() if alert else None,
                    "message": "Demo detection generated successfully",
                },
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Validation Error", "message": exc.message, "details": exc.details},
            )
        except PersistenceError as exc:
            logger.error("Persistence error during demo detection: %s", exc, exc_info=True)
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Database error", "message": "Failed to store demo detection"},
            )

    def _handle_ingest_event(self) -> None:
        """Ingest a single security event."""
        payload = self._read_json_body()
        if payload is None:
            return

        if not isinstance(payload, dict):
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Expected JSON object for SecurityEvent"},
            )
            return

        try:
            event, is_new = self.server.service.ingest_event(payload)
            if not is_new:
                # Deterministic response for duplicate event
                self._send_json_response(
                    HTTPStatus.CONFLICT,
                    {
                        "status": "duplicate",
                        "message": f"Event with ID '{event.event_id}' already exists",
                        "event_id": event.event_id,
                    },
                )
                return

            self._send_json_response(
                HTTPStatus.CREATED,
                {
                    "status": "created",
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "event_type": event.event_type.value,
                    "severity": event.severity.to_name(),
                },
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Validation Error", "message": exc.message, "details": exc.details},
            )
        except PersistenceError as exc:
            logger.error(f"Persistence error during ingestion: {exc}", exc_info=True)
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Database error", "message": "Failed to store security event"},
            )

    def _handle_ingest_batch(self) -> None:
        """Ingest a batch of security events."""
        payload = self._read_json_body()
        if payload is None:
            return

        items = payload.get("events") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Expected list of events under 'events' key or root array"},
            )
            return

        try:
            processed, new_count = self.server.service.ingest_batch(items)
            self._send_json_response(
                HTTPStatus.CREATED,
                {
                    "status": "processed",
                    "total_received": len(items),
                    "new_stored": new_count,
                    "duplicates": len(items) - new_count,
                },
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Batch Validation Error", "message": exc.message, "details": exc.details},
            )
        except PersistenceError as exc:
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Batch Database Error", "message": "Failed to persist batch"},
            )

    def _handle_get_single_event(self, event_id: str) -> None:
        """Retrieve a specific security event by ID."""
        event = self.server.service.get_event(event_id)
        if not event:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Event not found", "event_id": event_id},
            )
            return

        self._send_json_response(HTTPStatus.OK, event.to_dict())

    def _handle_query_events(self, params: dict[str, list[str]]) -> None:
        """Query events with filtering, bounded pagination, and deterministic ordering."""
        endpoint_id = params.get("endpoint_id", [None])[0]
        event_type = params.get("event_type", [None])[0]
        severity = params.get("severity", [None])[0]
        start_time = params.get("start_time", [None])[0]
        end_time = params.get("end_time", [None])[0]

        # Parse limit with bounds
        default_limit = self.server.config.default_page_limit
        max_limit = self.server.config.max_page_limit
        raw_limit = params.get("limit", [str(default_limit)])[0]
        try:
            limit = min(max(1, int(raw_limit)), max_limit)
        except ValueError:
            limit = default_limit

        # Parse offset
        raw_offset = params.get("offset", ["0"])[0]
        try:
            offset = max(0, int(raw_offset))
        except ValueError:
            offset = 0

        filter_params = EventQueryFilter(
            endpoint_id=endpoint_id,
            event_type=event_type,
            severity=severity,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )

        try:
            events, total = self.server.service.query_events(filter_params)
            response_data = {
                "total": total,
                "limit": limit,
                "offset": offset,
                "count": len(events),
                "events": [e.to_dict() for e in events],
            }
            self._send_json_response(HTTPStatus.OK, response_data)
        except PersistenceError as exc:
            logger.error(f"Error querying events: {exc}", exc_info=True)
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Query Error", "message": "Failed to retrieve events"},
            )

    def _handle_query_alerts(self, params: dict[str, list[str]]) -> None:
        """Query security alerts with filtering, bounded pagination, and deterministic ordering."""
        endpoint_id = params.get("endpoint_id", [None])[0]
        status = params.get("status", [None])[0]
        severity = params.get("severity", [None])[0]
        rule_id = params.get("rule_id", [None])[0]

        pid = None
        raw_pid = params.get("pid", [None])[0]
        if raw_pid:
            try:
                pid = int(raw_pid)
            except ValueError:
                pass

        min_score = None
        raw_min = params.get("min_score", [None])[0]
        if raw_min:
            try:
                min_score = int(raw_min)
            except ValueError:
                pass

        max_score = None
        raw_max = params.get("max_score", [None])[0]
        if raw_max:
            try:
                max_score = int(raw_max)
            except ValueError:
                pass

        start_time = params.get("start_time", [None])[0]
        end_time = params.get("end_time", [None])[0]
        order_by = params.get("order_by", ["created_at"])[0]
        desc = params.get("desc", ["true"])[0].lower() != "false"

        default_limit = self.server.config.default_page_limit
        max_limit = self.server.config.max_page_limit
        raw_limit = params.get("limit", [str(default_limit)])[0]
        try:
            limit = min(max(1, int(raw_limit)), max_limit)
        except ValueError:
            limit = default_limit

        raw_offset = params.get("offset", ["0"])[0]
        try:
            offset = max(0, int(raw_offset))
        except ValueError:
            offset = 0

        filter_params = AlertQueryFilter(
            endpoint_id=endpoint_id,
            status=status,
            severity=severity,
            rule_id=rule_id,
            pid=pid,
            min_score=min_score,
            max_score=max_score,
            start_time=start_time,
            end_time=end_time,
            order_by=order_by,
            desc=desc,
            limit=limit,
            offset=offset,
        )

        try:
            alerts, total = self.server.service.query_alerts(filter_params)
            response_data = {
                "total": total,
                "limit": limit,
                "offset": offset,
                "count": len(alerts),
                "alerts": [a.to_dict() for a in alerts],
            }
            self._send_json_response(HTTPStatus.OK, response_data)
        except PersistenceError as exc:
            logger.error(f"Error querying alerts: {exc}", exc_info=True)
            self._send_json_response(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Query Error", "message": "Failed to retrieve alerts"},
            )

    def _handle_get_single_alert(self, alert_id: str) -> None:
        """Retrieve a specific security alert by ID."""
        alert = self.server.service.get_alert(alert_id)
        if not alert:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Alert not found", "alert_id": alert_id},
            )
            return

        self._send_json_response(HTTPStatus.OK, alert.to_dict())

    def _handle_get_alert_evidence(self, alert_id: str) -> None:
        """Retrieve full evidence lineage for a specific security alert."""
        evidence_data = self.server.service.get_alert_evidence(alert_id)
        if not evidence_data:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Alert not found", "alert_id": alert_id},
            )
            return

        self._send_json_response(HTTPStatus.OK, evidence_data)

    def _handle_acknowledge_alert(self, alert_id: str) -> None:
        """Acknowledge a security alert."""
        body = self._read_optional_json_body()
        comment = body.get("comment") if isinstance(body, dict) else None

        alert = self.server.service.get_alert(alert_id)
        if not alert:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Alert not found", "alert_id": alert_id},
            )
            return

        try:
            updated = self.server.service.acknowledge_alert(alert_id, comment=comment)
            self._send_json_response(
                HTTPStatus.OK,
                {"status": "acknowledged", "alert": updated.to_dict() if updated else {}},
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid Transition", "message": exc.message},
            )

    def _handle_resolve_alert(self, alert_id: str) -> None:
        """Resolve a security alert."""
        body = self._read_optional_json_body()
        comment = body.get("comment") if isinstance(body, dict) else None

        alert = self.server.service.get_alert(alert_id)
        if not alert:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Alert not found", "alert_id": alert_id},
            )
            return

        try:
            updated = self.server.service.resolve_alert(alert_id, comment=comment)
            self._send_json_response(
                HTTPStatus.OK,
                {"status": "resolved", "alert": updated.to_dict() if updated else {}},
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid Transition", "message": exc.message},
            )

    def _handle_update_alert_status(self, alert_id: str) -> None:
        """Update lifecycle status of a security alert."""
        body = self._read_optional_json_body()
        target_status = body.get("status") if isinstance(body, dict) else None
        if not target_status:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing status", "message": "Expected 'status' field in request body"},
            )
            return

        comment = body.get("comment") if isinstance(body, dict) else None
        alert = self.server.service.get_alert(alert_id)
        if not alert:
            self._send_json_response(
                HTTPStatus.NOT_FOUND,
                {"error": "Alert not found", "alert_id": alert_id},
            )
            return

        try:
            updated = self.server.service.update_alert_status(
                alert_id, status=target_status, comment=comment
            )
            self._send_json_response(
                HTTPStatus.OK,
                {"status": "updated", "alert": updated.to_dict() if updated else {}},
            )
        except ValidationError as exc:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Invalid Transition", "message": exc.message},
            )

    # -------------------------------------------------------------------------
    # Advisory Recommendations Handler
    # -------------------------------------------------------------------------

    def _handle_get_alert_recommendations(self, alert_id: str) -> None:
        """Get advisory recommendations for an alert."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        alert = self.server.service.get_alert(alert_id)
        if not alert:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Alert not found", "alert_id": alert_id})
            return

        recs = self.server.service.get_alert_recommendations(alert_id)
        self._send_json_response(HTTPStatus.OK, {"alert_id": alert_id, "recommendations": recs})

    # -------------------------------------------------------------------------
    # Incident Handlers
    # -------------------------------------------------------------------------

    def _handle_create_incident(self) -> None:
        """Create a new security incident."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.MANAGE_INCIDENT)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_json_body()
        if body is None:
            return
        if not isinstance(body, dict):
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Expected JSON object"})
            return

        title = body.get("title")
        if not title:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing title", "message": "Field 'title' is required"})
            return

        try:
            incident = self.server.service.create_incident(
                title=title,
                description=body.get("description", ""),
                severity=body.get("severity", "HIGH"),
                assigned_to=body.get("assigned_to"),
                alert_ids=body.get("alert_ids"),
                user_context=ctx,
            )
            self._send_json_response(HTTPStatus.CREATED, {"status": "created", "incident": incident.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Failed to create incident", "message": str(exc)})

    def _handle_get_single_incident(self, incident_id: str) -> None:
        """Fetch a single incident by ID."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        incident = self.server.service.get_incident(incident_id)
        if not incident:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Incident not found", "incident_id": incident_id})
            return
        self._send_json_response(HTTPStatus.OK, incident.to_dict())

    def _handle_list_incidents(self, query_params: dict[str, list[str]]) -> None:
        """Query incidents with filtering and pagination."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        status = query_params.get("status", [None])[0]
        severity = query_params.get("severity", [None])[0]
        assigned_to = query_params.get("assigned_to", [None])[0]

        limit = self.server.config.default_page_limit
        if "limit" in query_params:
            try:
                limit = min(int(query_params["limit"][0]), self.server.config.max_page_limit)
            except ValueError:
                pass

        offset = 0
        if "offset" in query_params:
            try:
                offset = max(int(query_params["offset"][0]), 0)
            except ValueError:
                pass

        incidents, total = self.server.service.list_incidents(
            status=status,
            severity=severity,
            assigned_to=assigned_to,
            limit=limit,
            offset=offset,
        )
        self._send_json_response(
            HTTPStatus.OK,
            {
                "total": total,
                "count": len(incidents),
                "limit": limit,
                "offset": offset,
                "incidents": [i.to_dict() for i in incidents],
            },
        )

    def _handle_update_incident_status(self, incident_id: str) -> None:
        """Update incident lifecycle status."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.MANAGE_INCIDENT)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_json_body()
        if body is None:
            return
        new_status = body.get("status") if isinstance(body, dict) else None
        if not new_status:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing status", "message": "Field 'status' is required"})
            return

        incident = self.server.service.get_incident(incident_id)
        if not incident:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Incident not found", "incident_id": incident_id})
            return

        try:
            updated = self.server.service.update_incident_status(incident_id, new_status, ctx)
            self._send_json_response(HTTPStatus.OK, {"status": "updated", "incident": updated.to_dict()})
        except ValueError as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Invalid Transition", "message": str(exc)})

    def _handle_add_incident_note(self, incident_id: str) -> None:
        """Add an analyst note to an incident."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.MANAGE_INCIDENT)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_json_body()
        if body is None:
            return
        content = body.get("content") if isinstance(body, dict) else None
        if not content:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing content", "message": "Field 'content' is required"})
            return

        author = body.get("author") or ctx.username
        incident = self.server.service.get_incident(incident_id)
        if not incident:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Incident not found", "incident_id": incident_id})
            return

        note = self.server.service.add_incident_note(incident_id, author, content, ctx)
        self._send_json_response(HTTPStatus.CREATED, {"status": "created", "note": note.to_dict()})

    def _handle_associate_incident_alert(self, incident_id: str) -> None:
        """Associate an alert with an incident."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.MANAGE_INCIDENT)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_json_body()
        if body is None:
            return
        alert_id = body.get("alert_id") if isinstance(body, dict) else None
        if not alert_id:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing alert_id"})
            return

        incident = self.server.service.get_incident(incident_id)
        if not incident:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Incident not found", "incident_id": incident_id})
            return

        updated = self.server.service.associate_incident_alert(incident_id, alert_id, ctx)
        self._send_json_response(HTTPStatus.OK, {"status": "associated", "incident": updated.to_dict()})

    # -------------------------------------------------------------------------
    # Response Action Handlers
    # -------------------------------------------------------------------------

    def _handle_request_response_action(self) -> None:
        """Request a defensive response action (status: REQUESTED)."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.REQUEST_RESPONSE)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_json_body()
        if body is None:
            return
        if not isinstance(body, dict):
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Expected JSON object"})
            return

        action_type = body.get("action_type")
        if not action_type:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing action_type"})
            return

        target_params = body.get("target_params", {})
        if not isinstance(target_params, dict):
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "target_params must be a dictionary"})
            return

        try:
            # Accept friendly dashboard aliases and normalize them to the canonical enum.
            canonical_type = normalize_response_action_type(action_type)
            action = self.server.service.request_response_action(
                action_type=canonical_type,
                target_params=target_params,
                incident_id=body.get("incident_id"),
                alert_id=body.get("alert_id"),
                user_context=ctx,
            )
            self._send_json_response(HTTPStatus.CREATED, {"status": "requested", "action": action.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Failed to request response action", "message": str(exc)})

    def _handle_get_single_response(self, action_id: str) -> None:
        """Get response action details."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        action = self.server.service.get_response_action(action_id)
        if not action:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Response action not found", "action_id": action_id})
            return
        self._send_json_response(HTTPStatus.OK, action.to_dict())

    def _handle_list_responses(self, query_params: dict[str, list[str]]) -> None:
        """Query response actions with filtering and pagination."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        status = query_params.get("status", [None])[0]
        action_type = query_params.get("action_type", [None])[0]
        incident_id = query_params.get("incident_id", [None])[0]
        alert_id = query_params.get("alert_id", [None])[0]

        limit = self.server.config.default_page_limit
        if "limit" in query_params:
            try:
                limit = min(int(query_params["limit"][0]), self.server.config.max_page_limit)
            except ValueError:
                pass

        offset = 0
        if "offset" in query_params:
            try:
                offset = max(int(query_params["offset"][0]), 0)
            except ValueError:
                pass

        actions, total = self.server.service.list_response_actions(
            status=status,
            action_type=action_type,
            incident_id=incident_id,
            alert_id=alert_id,
            limit=limit,
            offset=offset,
        )
        self._send_json_response(
            HTTPStatus.OK,
            {
                "total": total,
                "count": len(actions),
                "limit": limit,
                "offset": offset,
                "actions": [a.to_dict() for a in actions],
            },
        )

    def _handle_authorize_response_action(self, action_id: str) -> None:
        """Authorize a requested action."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.AUTHORIZE_RESPONSE)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        try:
            action = self.server.service.authorize_response_action(action_id, ctx)
            self._send_json_response(HTTPStatus.OK, {"status": "authorized", "action": action.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Authorization failed", "message": str(exc)})

    def _handle_reject_response_action(self, action_id: str) -> None:
        """Reject a requested action."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.AUTHORIZE_RESPONSE)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        body = self._read_optional_json_body()
        reason = body.get("reason", "Rejected by analyst") if isinstance(body, dict) else "Rejected by analyst"

        try:
            action = self.server.service.reject_response_action(action_id, reason, ctx)
            self._send_json_response(HTTPStatus.OK, {"status": "rejected", "action": action.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Rejection failed", "message": str(exc)})

    def _handle_execute_response_action(self, action_id: str) -> None:
        """Execute an authorized action."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.EXECUTE_RESPONSE)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        try:
            action = self.server.service.execute_response_action(action_id, ctx)
            status_code = HTTPStatus.OK if action.status == ActionStatus.SUCCEEDED else HTTPStatus.BAD_REQUEST
            self._send_json_response(status_code, {"status": action.status.value, "action": action.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Execution failed", "message": str(exc)})

    def _handle_rollback_response_action(self, action_id: str) -> None:
        """Rollback a previously succeeded response action."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.EXECUTE_RESPONSE)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        try:
            action = self.server.service.rollback_response_action(action_id, ctx)
            self._send_json_response(HTTPStatus.OK, {"status": "rolled_back", "action": action.to_dict()})
        except Exception as exc:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Rollback failed", "message": str(exc)})

    # -------------------------------------------------------------------------
    # Audit Log Handlers
    # -------------------------------------------------------------------------

    def _handle_list_audit(self, query_params: dict[str, list[str]]) -> None:
        """Query immutable audit log entries."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        target_id = query_params.get("target_id", [None])[0]
        action = query_params.get("action", [None])[0]
        actor = query_params.get("actor", [None])[0]
        start_time = query_params.get("start_time", [None])[0]
        end_time = query_params.get("end_time", [None])[0]

        limit = self.server.config.default_page_limit
        if "limit" in query_params:
            try:
                limit = min(int(query_params["limit"][0]), self.server.config.max_page_limit)
            except ValueError:
                pass

        offset = 0
        if "offset" in query_params:
            try:
                offset = max(int(query_params["offset"][0]), 0)
            except ValueError:
                pass

        entries, total = self.server.service.list_audit_logs(
            target_id=target_id,
            action=action,
            actor=actor,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
        )
        self._send_json_response(
            HTTPStatus.OK,
            {
                "total": total,
                "count": len(entries),
                "limit": limit,
                "offset": offset,
                "audit_logs": [e.to_dict() for e in entries],
            },
        )

    def _handle_get_single_audit(self, audit_id: str) -> None:
        """Get single audit log entry."""
        try:
            ctx = self._get_user_context()
            ctx.require_permission(Permission.READ_SECURITY_DATA)
        except AuthorizationError as exc:
            self._send_json_response(HTTPStatus.FORBIDDEN, {"error": "Forbidden", "message": str(exc)})
            return

        entry = self.server.service.get_audit_log(audit_id)
        if not entry:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Audit entry not found", "audit_id": audit_id})
            return
        self._send_json_response(HTTPStatus.OK, entry.to_dict())


class BackendHTTPServer(http.server.ThreadingHTTPServer):
    """Custom ThreadingHTTPServer holding service and configuration state."""

    def __init__(
        self,
        server_address: tuple[str, int],
        service: EventService,
        config: BackendConfig,
        auth_tokens: dict[str, str] | None = None,
    ) -> None:
        super().__init__(server_address, EventIngestionHandler)
        self.service = service
        self.config = config
        self.auth_tokens = auth_tokens or {}
        self.daemon_threads = True


class BackendServer:
    """Manages the lifecycle of the backend HTTP server."""

    def __init__(
        self,
        service: EventService,
        config: BackendConfig | None = None,
        auth_tokens: dict[str, str] | None = None,
    ) -> None:
        self.service = service
        self.config = config or BackendConfig()
        self.auth_tokens = auth_tokens or {}
        self._server: BackendHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._is_running = False
        self._assigned_port: int | None = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def port(self) -> int:
        """Return the effective port the server is listening on."""
        if self._assigned_port:
            return self._assigned_port
        return self.config.port

    @property
    def host(self) -> str:
        return self.config.host

    def start(self, blocking: bool = False) -> None:
        """Start the backend server.

        If blocking is True, runs on current thread.
        Otherwise, runs in a background daemon thread.
        """
        with self._lock:
            if self._is_running:
                logger.warning("BackendServer is already running")
                return

            server_address = (self.config.host, self.config.port)
            self._server = BackendHTTPServer(
                server_address, self.service, self.config, auth_tokens=self.auth_tokens
            )
            self._assigned_port = self._server.server_port
            self._is_running = True

            logger.info(
                f"Backend HTTP Server started on http://{self.config.host}:{self._assigned_port}"
            )

            if blocking:
                try:
                    self._server.serve_forever()
                finally:
                    self.stop()
            else:
                self._thread = threading.Thread(
                    target=self._server.serve_forever,
                    name="TrojanDefense-HTTPServer",
                    daemon=True,
                )
                self._thread.start()

    def stop(self) -> None:
        """Stop the HTTP server and release port."""
        with self._lock:
            if not self._is_running:
                return

            logger.info("Stopping backend HTTP server...")
            if self._server:
                self._server.shutdown()
                self._server.server_close()
                self._server = None

            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3.0)
                self._thread = None

            self._is_running = False
            logger.info("Backend HTTP server stopped.")

    def __enter__(self) -> "BackendServer":
        self.start(blocking=False)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
