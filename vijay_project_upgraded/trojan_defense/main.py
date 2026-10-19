"""Main entry point and CLI runner for the Trojan Defense framework."""

import argparse
import json
import logging
from pathlib import Path
import signal
import sys
import time

from trojan_defense.backend.server import BackendServer
from trojan_defense.backend.service import EventService
from trojan_defense.core.exceptions import TrojanDefenseError
from trojan_defense.core.lifecycle.manager import ApplicationManager
from trojan_defense.core.logging.setup import get_logger
from trojan_defense.core.models.context import EventContext, ProcessContext
from trojan_defense.core.models.event import SecurityEvent
from trojan_defense.core.models.event_type import EventCategory, EventType
from trojan_defense.core.models.severity import Severity
from trojan_defense.response.auth import Role, UserContext
from trojan_defense.response.models import Incident, IncidentNote, ResponseActionType

logger = get_logger("main")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Trojan Defense Framework — Cross-Platform Trojan Defense Monitoring System"
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to configuration JSON file",
    )
    parser.add_argument(
        "--env",
        "-e",
        type=str,
        default=None,
        choices=["development", "test", "production"],
        help="Target runtime environment",
    )

    parser.add_argument(
        "--enable-process-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows process monitoring telemetry collector",
    )
    parser.add_argument(
        "--process-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for process monitor (default: 0.5)",
    )
    parser.add_argument(
        "--enable-file-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows filesystem monitoring telemetry collector",
    )
    parser.add_argument(
        "--file-path",
        type=str,
        default=None,
        help="Root path to monitor for filesystem activity (overrides config)",
    )
    parser.add_argument(
        "--file-debounce-ms",
        type=int,
        default=None,
        help="Debounce window in ms for file modifications (default: 200)",
    )
    parser.add_argument(
        "--enable-network-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows network connection telemetry collector",
    )
    parser.add_argument(
        "--network-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for network monitor (default: 1.0)",
    )
    parser.add_argument(
        "--no-network-loopback",
        action="store_true",
        default=False,
        help="Exclude loopback network connections from monitoring",
    )
    parser.add_argument(
        "--enable-system-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows system and privilege telemetry collector",
    )
    parser.add_argument(
        "--system-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for system monitor (default: 2.0)",
    )
    parser.add_argument(
        "--enable-deception",
        action="store_true",
        default=False,
        help="Enable the Cyber Deception Engine",
    )
    parser.add_argument(
        "--deception-root",
        type=str,
        default=None,
        help="Root directory for synthetic deception artifacts",
    )
    parser.add_argument(
        "--disable-deception-detection",
        action="store_true",
        default=False,
        help="Disable automatic deception interaction detection",
    )
    parser.add_argument(
        "--deception-debounce-ms",
        type=int,
        default=None,
        help="Debounce window in ms for repeated decoy interactions (default: 200)",
    )
    parser.add_argument(
        "--enable-behavior",
        action="store_true",
        default=False,
        help="Enable the Behavioral Correlation and Detection Engine",
    )
    parser.add_argument(
        "--correlation-window",
        type=float,
        default=None,
        help="Behavioral correlation time window in seconds (default: 60.0)",
    )
    parser.add_argument(
        "--dedup-window",
        type=float,
        default=None,
        help="Behavioral finding deduplication window in seconds (default: 30.0)",
    )
    parser.add_argument(
        "--enable-alerting",
        action="store_true",
        default=False,
        help="Enable the Risk Scoring and Alert Generation Engine",
    )
    parser.add_argument(
        "--min-alert-score",
        type=int,
        default=None,
        help="Minimum risk score required to produce an alert (default: 20)",
    )
    parser.add_argument(
        "--alert-dedup-window",
        type=float,
        default=None,
        help="Alert deduplication window in seconds (default: 60.0)",
    )
    parser.add_argument(
        "--alert-cooldown",
        type=float,
        default=None,
        help="Alert cooldown suppression window in seconds (default: 300.0)",
    )
    parser.add_argument(
        "--enable-response",
        action="store_true",
        default=False,
        help="Enable the Controlled Defensive Response and Incident Management subsystem",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=str,
        default=None,
        help="Directory path for file quarantine storage",
    )

    subparsers = parser.add_subparsers(dest="command", help="Operational commands")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Start the application and run event pipeline")
    run_parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=None,
        help="Duration in seconds to run before exiting (default: run until interrupted)",
    )
    run_parser.add_argument(
        "--enable-process-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows process monitoring telemetry collector",
    )
    run_parser.add_argument(
        "--process-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for process monitor (default: 0.5)",
    )
    run_parser.add_argument(
        "--enable-file-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows filesystem monitoring telemetry collector",
    )
    run_parser.add_argument(
        "--file-path",
        type=str,
        default=None,
        help="Root path to monitor for filesystem activity (overrides config)",
    )
    run_parser.add_argument(
        "--file-debounce-ms",
        type=int,
        default=None,
        help="Debounce window in ms for file modifications (default: 200)",
    )
    run_parser.add_argument(
        "--enable-network-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows network connection telemetry collector",
    )
    run_parser.add_argument(
        "--network-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for network monitor (default: 1.0)",
    )
    run_parser.add_argument(
        "--no-network-loopback",
        action="store_true",
        default=False,
        help="Exclude loopback network connections from monitoring",
    )
    run_parser.add_argument(
        "--enable-system-monitor",
        action="store_true",
        default=False,
        help="Enable the Windows system and privilege telemetry collector",
    )
    run_parser.add_argument(
        "--system-interval",
        type=float,
        default=None,
        help="Polling interval in seconds for system monitor (default: 2.0)",
    )
    run_parser.add_argument(
        "--enable-deception",
        action="store_true",
        default=False,
        help="Enable the Cyber Deception Engine",
    )
    run_parser.add_argument(
        "--deception-root",
        type=str,
        default=None,
        help="Root directory for synthetic deception artifacts",
    )
    run_parser.add_argument(
        "--disable-deception-detection",
        action="store_true",
        default=False,
        help="Disable automatic deception interaction detection",
    )
    run_parser.add_argument(
        "--deception-debounce-ms",
        type=int,
        default=None,
        help="Debounce window in ms for repeated decoy interactions (default: 200)",
    )
    run_parser.add_argument(
        "--enable-behavior",
        action="store_true",
        default=False,
        help="Enable the Behavioral Correlation and Detection Engine",
    )
    run_parser.add_argument(
        "--correlation-window",
        type=float,
        default=None,
        help="Behavioral correlation time window in seconds (default: 60.0)",
    )
    run_parser.add_argument(
        "--dedup-window",
        type=float,
        default=None,
        help="Behavioral finding deduplication window in seconds (default: 30.0)",
    )
    run_parser.add_argument(
        "--enable-alerting",
        action="store_true",
        default=False,
        help="Enable the Risk Scoring and Alert Generation Engine",
    )
    run_parser.add_argument(
        "--min-alert-score",
        type=int,
        default=None,
        help="Minimum risk score required to produce an alert (default: 20)",
    )
    run_parser.add_argument(
        "--alert-dedup-window",
        type=float,
        default=None,
        help="Alert deduplication window in seconds (default: 60.0)",
    )
    run_parser.add_argument(
        "--alert-cooldown",
        type=float,
        default=None,
        help="Alert cooldown suppression window in seconds (default: 300.0)",
    )
    run_parser.add_argument(
        "--enable-response",
        action="store_true",
        default=False,
        help="Enable the Controlled Defensive Response and Incident Management subsystem",
    )
    run_parser.add_argument(
        "--quarantine-dir",
        type=str,
        default=None,
        help="Directory path for file quarantine storage",
    )

    # Command: server
    server_parser = subparsers.add_parser(
        "server", help="Start the backend event ingestion and querying server"
    )
    server_parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host address to bind server (overrides configuration)",
    )
    server_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        help="Port to bind server (overrides configuration)",
    )
    server_parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=None,
        help="Duration in seconds to run server before stopping",
    )

    # Command: deception
    deception_parser = subparsers.add_parser(
        "deception", help="Manage deception artifacts and registry"
    )
    deception_parser.add_argument(
        "action",
        choices=["deploy", "cleanup", "status"],
        help="Action to perform (deploy, cleanup, status)",
    )

    # Command: incident
    incident_parser = subparsers.add_parser("incident", help="Manage security incidents")
    incident_parser.add_argument("action", choices=["list", "create", "status", "note"], help="Incident action")
    incident_parser.add_argument("--id", type=str, default=None, help="Incident ID")
    incident_parser.add_argument("--title", type=str, default=None, help="Incident title")
    incident_parser.add_argument("--severity", type=str, default="HIGH", help="Incident severity")
    incident_parser.add_argument("--description", type=str, default="", help="Incident description")
    incident_parser.add_argument("--status", type=str, default=None, help="New incident status")
    incident_parser.add_argument("--content", type=str, default=None, help="Note content")
    incident_parser.add_argument("--author", type=str, default="analyst", help="Note author")

    # Command: response
    response_parser = subparsers.add_parser("response", help="Manage defensive response actions")
    response_parser.add_argument(
        "action",
        choices=["list", "request", "authorize", "reject", "execute", "rollback"],
        help="Response action operation",
    )
    response_parser.add_argument("--id", type=str, default=None, help="Action ID")
    response_parser.add_argument("--type", type=str, default=None, help="Response action type")
    response_parser.add_argument("--params", type=str, default="{}", help="Target params as JSON string")
    response_parser.add_argument("--incident-id", type=str, default=None, help="Associated incident ID")
    response_parser.add_argument("--alert-id", type=str, default=None, help="Associated alert ID")
    response_parser.add_argument("--reason", type=str, default="Analyst review", help="Rejection reason")
    response_parser.add_argument("--user", type=str, default="analyst", help="Executing user")
    response_parser.add_argument("--role", type=str, default="ADMIN", help="User role")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Inspect immutable audit logs")
    audit_parser.add_argument("action", choices=["list", "get"], help="Audit action")
    audit_parser.add_argument("--id", type=str, default=None, help="Audit log ID")
    audit_parser.add_argument("--target", type=str, default=None, help="Target ID filter")
    audit_parser.add_argument("--actor", type=str, default=None, help="Actor filter")

    # Command: validate-config
    subparsers.add_parser("validate-config", help="Validate configuration and exit")

    # Command: status
    subparsers.add_parser("status", help="Print endpoint identity and configuration summary")

    # Command: test-event
    subparsers.add_parser("test-event", help="Send a test SecurityEvent through the pipeline")

    return parser.parse_args(argv)


def run_app(manager: ApplicationManager, duration: float | None = None) -> int:
    """Start application and keep running until signal or duration expires."""
    stop_event = False

    def handle_signal(sig: int, frame: object) -> None:
        nonlocal stop_event
        logger.info(f"Received exit signal ({sig}), initiating shutdown...")
        stop_event = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    manager.start()
    start_time = time.time()

    try:
        while not stop_event:
            time.sleep(0.5)
            if duration and (time.time() - start_time) >= duration:
                logger.info(f"Execution duration of {duration}s reached.")
                break
    finally:
        manager.stop()

    return 0


def run_server(
    manager: ApplicationManager,
    host: str | None = None,
    port: int | None = None,
    duration: float | None = None,
) -> int:
    """Start the backend event ingestion server."""
    assert manager.config is not None
    assert manager.repository is not None

    if host:
        manager.config.backend.host = host
    if port:
        manager.config.backend.port = port

    service = EventService(
        repository=manager.repository,
        alert_repository=manager.alert_repository,
        alert_engine=manager.alert_engine,
        incident_repository=manager.incident_repository,
        response_action_repository=manager.response_action_repository,
        response_executor=manager.response_executor,
        response_recommender=manager.response_recommender,
        audit_repository=manager.audit_repository,
    )
    auth_tokens = (
        manager.config.response.auth_tokens if manager.config and manager.config.response else None
    )
    server = BackendServer(
        service=service, config=manager.config.backend, auth_tokens=auth_tokens
    )

    stop_event = False

    def handle_signal(sig: int, frame: object) -> None:
        nonlocal stop_event
        logger.info(f"Received exit signal ({sig}), shutting down server...")
        stop_event = True

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    server.start(blocking=False)
    start_time = time.time()

    try:
        while not stop_event:
            time.sleep(0.5)
            if duration and (time.time() - start_time) >= duration:
                logger.info(f"Server execution duration of {duration}s reached.")
                break
    finally:
        server.stop()
        manager.stop()

    return 0


def main(argv: list[str] | None = None) -> int:
    """Application CLI entry point."""
    args = parse_args(argv)
    manager = ApplicationManager()

    try:
        from trojan_defense.core.config.loader import load_config
        cfg = load_config(config_file=args.config, environment=args.env)
        if getattr(args, "enable_process_monitor", False):
            cfg.process_collector.enabled = True
            cfg.collectors.process = True
        if getattr(args, "process_interval", None) is not None:
            cfg.process_collector.polling_interval = args.process_interval
        if getattr(args, "enable_file_monitor", False):
            cfg.file_collector.enabled = True
            cfg.collectors.file = True
        if getattr(args, "file_path", None):
            cfg.file_collector.monitored_paths = [args.file_path]
        if getattr(args, "file_debounce_ms", None) is not None:
            cfg.file_collector.debounce_ms = args.file_debounce_ms
        if getattr(args, "enable_network_monitor", False):
            cfg.network_collector.enabled = True
            cfg.collectors.network = True
        if getattr(args, "network_interval", None) is not None:
            cfg.network_collector.polling_interval = args.network_interval
        if getattr(args, "no_network_loopback", False):
            cfg.network_collector.include_loopback = False
        if getattr(args, "enable_system_monitor", False):
            cfg.system_collector.enabled = True
            cfg.collectors.system = True
        if getattr(args, "system_interval", None) is not None:
            cfg.system_collector.polling_interval = args.system_interval
        if getattr(args, "enable_deception", False):
            cfg.deception.enabled = True
            cfg.collectors.deception = True
        if getattr(args, "deception_root", None):
            cfg.deception.deception_root = args.deception_root
        if getattr(args, "disable_deception_detection", False):
            cfg.deception.interaction_detection_enabled = False
        if getattr(args, "deception_debounce_ms", None) is not None:
            cfg.deception.interaction_debounce_ms = args.deception_debounce_ms
        if getattr(args, "enable_behavior", False):
            cfg.behavior.enabled = True
            cfg.collectors.behavior = True
        if getattr(args, "correlation_window", None) is not None:
            cfg.behavior.correlation_window_seconds = args.correlation_window
        if getattr(args, "dedup_window", None) is not None:
            cfg.behavior.dedup_window_seconds = args.dedup_window
        if getattr(args, "enable_alerting", False):
            cfg.alerting.enabled = True
            cfg.collectors.alerting = True
        if getattr(args, "min_alert_score", None) is not None:
            cfg.alerting.min_alert_score = args.min_alert_score
        if getattr(args, "alert_dedup_window", None) is not None:
            cfg.alerting.dedup_window_seconds = args.alert_dedup_window
        if getattr(args, "alert_cooldown", None) is not None:
            cfg.alerting.cooldown_seconds = args.alert_cooldown
        if getattr(args, "enable_response", False):
            cfg.response.enabled = True
            cfg.collectors.response = True
        if getattr(args, "quarantine_dir", None):
            cfg.response.quarantine_dir = args.quarantine_dir

        manager.initialize(config=cfg)

        if args.command in (None, "run"):
            duration = getattr(args, "duration", None)
            return run_app(manager, duration=duration)

        elif args.command == "server":
            host = getattr(args, "host", None)
            port = getattr(args, "port", None)
            duration = getattr(args, "duration", None)
            return run_server(manager, host=host, port=port, duration=duration)

        elif args.command == "incident":
            action = getattr(args, "action", "list")
            user_ctx = UserContext(username=getattr(args, "author", "analyst"), role=Role.ADMIN)
            if not manager.incident_repository:
                logger.error("Incident repository is not initialized. Ensure response subsystem is enabled.")
                return 1

            if action == "list":
                incidents, total = manager.incident_repository.list()
                logger.info(f"Total Incidents: {total}")
                for inc in incidents:
                    logger.info(f"  - [{inc.status.value}] {inc.incident_id}: {inc.title} (Severity: {inc.severity}, Alerts: {len(inc.alert_ids)})")
                return 0
            elif action == "create":
                inc = manager.incident_repository.create(
                    Incident(
                        title=args.title or "Security Incident",
                        description=args.description or "",
                        severity=args.severity or "HIGH",
                        assigned_to=args.author,
                    )
                )
                logger.info(f"Created Incident: {inc.incident_id} [{inc.status.value}] - {inc.title}")
                return 0
            elif action == "status":
                if not args.id or not args.status:
                    logger.error("Missing --id or --status for incident status update")
                    return 1
                inc = manager.incident_repository.get(args.id)
                if not inc:
                    logger.error(f"Incident {args.id} not found")
                    return 1
                inc.transition_to(args.status)
                manager.incident_repository.update(inc)
                logger.info(f"Updated Incident {inc.incident_id} status to {inc.status.value}")
                return 0
            elif action == "note":
                if not args.id or not args.content:
                    logger.error("Missing --id or --content for incident note")
                    return 1
                note = manager.incident_repository.add_note(
                    args.id, IncidentNote(incident_id=args.id, author=args.author, content=args.content)
                )
                logger.info(f"Added note {note.note_id} to Incident {args.id}")
                return 0

        elif args.command == "response":
            action = getattr(args, "action", "list")
            user_role = Role(getattr(args, "role", "ADMIN").upper())
            user_ctx = UserContext(username=getattr(args, "user", "analyst"), role=user_role)

            if not manager.response_action_repository or not manager.response_executor:
                logger.error("Response subsystem is not initialized.")
                return 1

            if action == "list":
                actions, total = manager.response_action_repository.list()
                logger.info(f"Total Response Actions: {total}")
                for a in actions:
                    logger.info(f"  - [{a.status.value}] {a.action_id}: {a.action_type.value} (Target: {a.target_params})")
                return 0
            elif action == "request":
                if not args.type:
                    logger.error("Missing --type for response request")
                    return 1
                try:
                    params = json.loads(args.params)
                except Exception:
                    params = {}
                act = manager.response_executor.request_action(
                    action_type=args.type,
                    target_params=params,
                    incident_id=getattr(args, "incident_id", None),
                    alert_id=getattr(args, "alert_id", None),
                    user_context=user_ctx,
                )
                logger.info(f"Requested Response Action: {act.action_id} [{act.status.value}]")
                return 0
            elif action == "authorize":
                if not args.id:
                    logger.error("Missing --id for authorization")
                    return 1
                act = manager.response_executor.authorize_action(args.id, user_ctx)
                logger.info(f"Authorized Response Action: {act.action_id} [{act.status.value}]")
                return 0
            elif action == "reject":
                if not args.id:
                    logger.error("Missing --id for rejection")
                    return 1
                act = manager.response_executor.reject_action(args.id, args.reason, user_ctx)
                logger.info(f"Rejected Response Action: {act.action_id} [{act.status.value}]")
                return 0
            elif action == "execute":
                if not args.id:
                    logger.error("Missing --id for execution")
                    return 1
                act = manager.response_executor.execute_action(args.id, user_ctx)
                logger.info(f"Executed Response Action: {act.action_id} [{act.status.value}]")
                return 0
            elif action == "rollback":
                if not args.id:
                    logger.error("Missing --id for rollback")
                    return 1
                act = manager.response_executor.rollback_action(args.id, user_ctx)
                logger.info(f"Rolled back Response Action: {act.action_id} [{act.status.value}]")
                return 0

        elif args.command == "audit":
            action = getattr(args, "action", "list")
            if not manager.audit_repository:
                logger.error("Audit repository is not initialized.")
                return 1

            if action == "list":
                entries, total = manager.audit_repository.list(
                    target_id=getattr(args, "target", None),
                    actor=getattr(args, "actor", None),
                )
                logger.info(f"Total Audit Entries: {total}")
                for e in entries:
                    logger.info(f"  - [{e.timestamp}] {e.action.value} by {e.actor} ({e.role}) on {e.target_type}:{e.target_id}")
                return 0
            elif action == "get":
                if not args.id:
                    logger.error("Missing --id for audit get")
                    return 1
                entry = manager.audit_repository.get(args.id)
                if not entry:
                    logger.error(f"Audit entry {args.id} not found")
                    return 1
                logger.info(f"Audit Entry: {entry.to_dict()}")
                return 0

        elif args.command == "deception":
            action = getattr(args, "action", "status")
            if not manager.deception_engine:
                from trojan_defense.deception.engine import CyberDeceptionEngine
                manager.config.deception.enabled = True
                manager.deception_engine = CyberDeceptionEngine(
                    config=manager.config.deception,
                    repository=manager.repository,
                )
                manager.deception_engine.initialize()

            if action == "deploy":
                deployed = manager.deception_engine.deploy()
                logger.info(f"Deployed {len(deployed)} synthetic decoys successfully.")
                return 0
            elif action == "cleanup":
                cleaned = manager.deception_engine.cleanup()
                logger.info(f"Cleaned up {len(cleaned)} decoys successfully.")
                return 0
            elif action == "status":
                st = manager.deception_engine.status()
                logger.info(f"Deception Status: active={st['active_decoys']}/{st['total_registered']}, root='{st['deception_root']}'")
                for d in st["decoys"]:
                    logger.info(f"  - [{d['status']}] {d['decoy_id']} ({d['artifact_type']}) -> {d['relative_path']}")
                return 0

        elif args.command == "validate-config":
            logger.info("Configuration is valid and successfully verified.")
            return 0

        elif args.command == "status":
            assert manager.config is not None
            assert manager.endpoint is not None
            logger.info(f"Environment: {manager.config.app.environment}")
            logger.info(f"Endpoint ID: {manager.endpoint.endpoint_id}")
            logger.info(f"Hostname: {manager.endpoint.hostname}")
            logger.info(f"Platform: {manager.endpoint.platform} ({manager.endpoint.os_version})")
            logger.info(f"Architecture: {manager.endpoint.architecture}")
            logger.info(f"Agent Version: {manager.endpoint.agent_version}")
            logger.info(
                f"Persistence Driver: {manager.config.persistence.driver} (enabled={manager.config.persistence.enabled})"
            )
            logger.info(
                f"Transport Driver: {manager.config.transport.driver} (enabled={manager.config.transport.enabled})"
            )
            logger.info(
                f"Process Monitor: enabled={manager.config.process_collector.enabled} (interval={manager.config.process_collector.polling_interval}s)"
            )
            logger.info(
                f"File Monitor: enabled={manager.config.file_collector.enabled} (roots={manager.config.file_collector.monitored_paths}, debounce={manager.config.file_collector.debounce_ms}ms)"
            )
            logger.info(
                f"Network Monitor: enabled={manager.config.network_collector.enabled} (interval={manager.config.network_collector.polling_interval}s, loopback={manager.config.network_collector.include_loopback})"
            )
            logger.info(
                f"System Monitor: enabled={manager.config.system_collector.enabled} (interval={manager.config.system_collector.polling_interval}s, sessions={manager.config.system_collector.monitor_sessions}, privileges={manager.config.system_collector.monitor_privileges})"
            )
            logger.info(
                f"Deception Engine: enabled={manager.config.deception.enabled} (root='{manager.config.deception.deception_root}', "
                f"auto_create={manager.config.deception.auto_create_on_startup}, "
                f"interaction_detection={manager.config.deception.interaction_detection_enabled})"
            )
            logger.info(
                f"Behavior Engine: enabled={manager.config.behavior.enabled} (window={manager.config.behavior.correlation_window_seconds}s, "
                f"dedup={manager.config.behavior.dedup_window_seconds}s, max_tracked={manager.config.behavior.max_tracked_processes})"
            )
            logger.info(
                f"Alerting Engine: enabled={manager.config.alerting.enabled} (min_score={manager.config.alerting.min_alert_score}, "
                f"dedup={manager.config.alerting.dedup_window_seconds}s, cooldown={manager.config.alerting.cooldown_seconds}s)"
            )
            logger.info(
                f"Response Subsystem: enabled={manager.config.response.enabled} (quarantine='{manager.config.response.quarantine_dir}', "
                f"require_auth={manager.config.response.require_authorization})"
            )
            logger.info(
                f"Backend Server: {manager.config.backend.host}:{manager.config.backend.port}"
            )
            return 0

        elif args.command == "test-event":
            manager.start()
            try:
                assert manager.pipeline is not None
                assert manager.endpoint is not None
                # Create a sample SecurityEvent
                test_event = SecurityEvent(
                    event_type=EventType.from_category(EventCategory.SYSTEM),
                    severity=Severity.INFO,
                    source="foundation.test_runner",
                    endpoint=manager.endpoint,
                    context=EventContext(
                        process=ProcessContext(name="test_proc", pid=1234),
                    ),
                )
                logger.info(f"Submitting test event: {test_event.event_id}")
                processed = manager.pipeline.process(test_event)
                logger.info(f"Test event processed successfully! ID: {processed.event_id}")
                logger.info(f"Pipeline Stats: {manager.pipeline.stats}")
                return 0
            finally:
                manager.stop()

        return 0

    except TrojanDefenseError as exc:
        logger.error(f"Trojan Defense Error: {exc}")
        return 1
    except Exception as exc:
        logger.error(f"Fatal error: {exc}", exc_info=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
