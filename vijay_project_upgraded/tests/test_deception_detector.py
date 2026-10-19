"""Unit tests for Phase 8 Deception Interaction Detection.

Validates that interactions with registered Phase 7 decoys are faithfully
detected and emitted as DECEPTION.INTERACTION events while ordinary files and
unregistered files never trigger false positives, debounce suppresses bursts,
and original event contexts are preserved.
"""

from pathlib import Path
import tempfile
import time
import pytest

from trojan_defense.core.config.schema import DeceptionConfig
from trojan_defense.core.models.context import (
    DeceptionContext,
    EventContext,
    FileContext,
    ProcessContext,
    SystemContext,
)
from trojan_defense.core.models.event import (
    EventCategory,
    EventType,
    SecurityEvent,
    Severity,
    current_utc_timestamp,
)
from trojan_defense.core.models.identity import EndpointIdentity
from trojan_defense.core.pipeline.pipeline import EventPipeline
from trojan_defense.deception.detector import (
    DeceptionDetectionError,
    DeceptionInteractionDetector,
)
from trojan_defense.deception.models import DecoyDefinition, DecoyRecord, DecoyStatus, DecoyType
from trojan_defense.deception.registry import DecoyRegistry


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def endpoint():
    return EndpointIdentity(
        endpoint_id="ep-test-phase8",
        hostname="TEST-WORKSTATION",
        platform="Windows",
        os_version="10.0.19045",
        architecture="AMD64",
    )


@pytest.fixture
def decoy_registry(temp_dir):
    reg = DecoyRegistry(deception_root=temp_dir)
    # Register 2 active decoys
    p1 = temp_dir / "credentials" / "passwords.txt"
    p1.parent.mkdir(parents=True, exist_ok=True)
    p1.write_text("admin:secret123\n")

    p2 = temp_dir / "config" / "aws_keys.json"
    p2.parent.mkdir(parents=True, exist_ok=True)
    p2.write_text('{"aws_access_key_id": "AKIAIOSFODNN7EXAMPLE"}\n')

    d1 = DecoyRecord(
        decoy_id="decoy-cred-001",
        artifact_type=DecoyType.FILE.value,
        relative_path="credentials/passwords.txt",
        normalized_path=str(p1.resolve()),
        purpose="credential_canary",
        created_at=current_utc_timestamp(),
        status=DecoyStatus.ACTIVE.value,
    )
    d2 = DecoyRecord(
        decoy_id="decoy-key-002",
        artifact_type=DecoyType.FILE.value,
        relative_path="config/aws_keys.json",
        normalized_path=str(p2.resolve()),
        purpose="api_key_canary",
        created_at=current_utc_timestamp(),
        status=DecoyStatus.ACTIVE.value,
    )
    reg.register(d1)
    reg.register(d2)
    return reg


def make_file_event(
    action: str,
    path: str,
    previous_path: str | None = None,
    is_directory: bool = False,
    process_name: str | None = "explorer.exe",
    pid: int = 1234,
    endpoint: EndpointIdentity | None = None,
) -> SecurityEvent:
    """Helper to create a canonical FILE SecurityEvent."""
    ep = endpoint or EndpointIdentity(
        endpoint_id="ep-unit-test",
        hostname="HOST",
        platform="Windows",
        os_version="10.0",
        architecture="x64",
    )
    return SecurityEvent(
        event_type=EventType(EventCategory.FILE, action.upper()),
        severity=Severity.LOW,
        source="windows_file_monitor",
        endpoint=ep,
        context=EventContext(
            file=FileContext(
                path=str(path),
                operation=action.lower(),
                is_directory=is_directory,
                previous_path=str(previous_path) if previous_path else None,
            ),
            process=ProcessContext(name=process_name, pid=pid) if process_name else None,
            system=SystemContext(username="Administrator"),
        ),
        timestamp=current_utc_timestamp(),
    )


class TestDeceptionInteractionDetectorUnit:
    """Comprehensive unit testing of DeceptionInteractionDetector."""

    def test_detector_disabled_returns_none(self, decoy_registry, temp_dir):
        """When detection is disabled, analyze_event returns None."""
        cfg = DeceptionConfig(interaction_detection_enabled=False)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        assert not detector.is_enabled
        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event = make_file_event("MODIFY", str(decoy_path))

        res = detector.analyze_event(event)
        assert res is None

    def test_ordinary_file_returns_none(self, decoy_registry, temp_dir):
        """Ordinary file outside deception root returns None and triggers no interaction."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        ordinary_path = temp_dir.parent / "legit_documents" / "report.docx"
        event = make_file_event("MODIFY", str(ordinary_path))

        res = detector.analyze_event(event)
        assert res is None

    def test_unregistered_file_in_deception_root_returns_none(self, decoy_registry, temp_dir):
        """Unregistered file inside deception root returns None (prevents false positives)."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        unregistered_path = temp_dir / "credentials" / "unregistered_temp.log"
        event = make_file_event("CREATE", str(unregistered_path))

        res = detector.analyze_event(event)
        assert res is None

    def test_detect_decoy_modification(self, decoy_registry, temp_dir):
        """Modifying a registered decoy produces a HIGH-severity DECEPTION.INTERACTION event."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event = make_file_event("MODIFY", str(decoy_path), process_name="malware.exe", pid=666)

        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.event_type.category == EventCategory.DECEPTION
        assert interaction.event_type.action == "INTERACTION"
        assert interaction.severity == Severity.HIGH
        assert interaction.source == "deception_interaction_detector"

        # Verify deception context
        dctx = interaction.context.deception
        assert dctx is not None
        assert dctx.is_decoy is True
        assert dctx.decoy_id == "decoy-cred-001"
        assert dctx.decoy_type == DecoyType.FILE.value
        assert dctx.interaction_type == "modified"
        assert dctx.original_event_id == event.event_id

        # Verify preserved context
        assert interaction.context.process is not None
        assert interaction.context.process.name == "malware.exe"
        assert interaction.context.process.pid == 666
        assert interaction.context.system is not None
        assert interaction.context.system.username == "Administrator"
        assert interaction.context.file is not None

    def test_detect_decoy_deletion(self, decoy_registry, temp_dir):
        """Deleting a registered decoy produces a HIGH-severity DECEPTION.INTERACTION event."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "config" / "aws_keys.json"
        event = make_file_event("DELETE", str(decoy_path))

        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.severity == Severity.HIGH
        assert interaction.context.deception.interaction_type == "deleted"
        assert interaction.context.deception.decoy_id == "decoy-key-002"

    def test_detect_decoy_rename_target_or_previous(self, decoy_registry, temp_dir):
        """Renaming a registered decoy identifies it from previous_path."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        original_path = temp_dir / "credentials" / "passwords.txt"
        renamed_path = temp_dir / "credentials" / "passwords_stolen.bak"

        event = make_file_event("RENAME", str(renamed_path), previous_path=str(original_path))

        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.context.deception.interaction_type == "renamed"
        assert interaction.context.deception.decoy_id == "decoy-cred-001"

    def test_detect_decoy_creation_recreation(self, decoy_registry, temp_dir):
        """Creation event matching registered decoy produces created interaction."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event = make_file_event("CREATE", str(decoy_path))

        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.context.deception.interaction_type == "created"

    def test_detect_directory_events(self, decoy_registry, temp_dir):
        """Directory creation/deletion on registered decoy directory is tracked."""
        dir_path = temp_dir / "credentials"
        d_dir = DecoyRecord(
            decoy_id="decoy-dir-001",
            artifact_type=DecoyType.DIRECTORY.value,
            relative_path="credentials",
            normalized_path=str(dir_path.resolve()),
            purpose="directory_structure",
            created_at=current_utc_timestamp(),
            status=DecoyStatus.ACTIVE.value,
        )
        decoy_registry.register(d_dir)

        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        event = make_file_event("DIR_DELETE", str(dir_path), is_directory=True)
        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.context.deception.interaction_type == "dir_deleted"
        assert interaction.context.deception.decoy_id == "decoy-dir-001"

    def test_case_insensitive_path_matching(self, decoy_registry, temp_dir):
        """Windows path matching is strictly case-insensitive."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        # Upper case variant
        decoy_path = str(temp_dir / "credentials" / "passwords.txt").upper()
        event = make_file_event("MODIFY", decoy_path)

        interaction = detector.analyze_event(event)
        assert interaction is not None
        assert interaction.context.deception.decoy_id == "decoy-cred-001"

    def test_debounce_suppresses_rapid_duplicate_interactions(self, decoy_registry, temp_dir):
        """Repeated interaction with the same decoy within debounce window is coalesced."""
        cfg = DeceptionConfig(interaction_detection_enabled=True, interaction_debounce_ms=500)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event1 = make_file_event("MODIFY", str(decoy_path))
        event2 = make_file_event("MODIFY", str(decoy_path))

        interaction1 = detector.analyze_event(event1)
        interaction2 = detector.analyze_event(event2)

        assert interaction1 is not None
        assert interaction2 is None  # Debounced

    def test_debounce_allows_after_window_expires(self, decoy_registry, temp_dir):
        """Interactions after debounce window expires are permitted."""
        cfg = DeceptionConfig(interaction_detection_enabled=True, interaction_debounce_ms=50)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event1 = make_file_event("MODIFY", str(decoy_path))
        interaction1 = detector.analyze_event(event1)
        assert interaction1 is not None

        time.sleep(0.08)  # Wait for 50ms window to expire

        event2 = make_file_event("MODIFY", str(decoy_path))
        interaction2 = detector.analyze_event(event2)
        assert interaction2 is not None

    def test_debounce_distinguishes_different_interaction_types(self, decoy_registry, temp_dir):
        """Different interaction types on the same decoy are both allowed."""
        cfg = DeceptionConfig(interaction_detection_enabled=True, interaction_debounce_ms=500)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        decoy_path = temp_dir / "credentials" / "passwords.txt"
        event_mod = make_file_event("MODIFY", str(decoy_path))
        event_del = make_file_event("DELETE", str(decoy_path))

        interaction1 = detector.analyze_event(event_mod)
        interaction2 = detector.analyze_event(event_del)

        assert interaction1 is not None
        assert interaction2 is not None
        assert interaction1.context.deception.interaction_type == "modified"
        assert interaction2.context.deception.interaction_type == "deleted"

    def test_debounce_distinguishes_different_decoys(self, decoy_registry, temp_dir):
        """Interactions on different decoys do not debounce each other."""
        cfg = DeceptionConfig(interaction_detection_enabled=True, interaction_debounce_ms=500)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        p1 = temp_dir / "credentials" / "passwords.txt"
        p2 = temp_dir / "config" / "aws_keys.json"

        event1 = make_file_event("MODIFY", str(p1))
        event2 = make_file_event("MODIFY", str(p2))

        interaction1 = detector.analyze_event(event1)
        interaction2 = detector.analyze_event(event2)

        assert interaction1 is not None
        assert interaction2 is not None
        assert interaction1.context.deception.decoy_id == "decoy-cred-001"
        assert interaction2.context.deception.decoy_id == "decoy-key-002"

    def test_invalid_or_malformed_event_handling(self, decoy_registry):
        """Events without file context or invalid data return None without crashing."""
        cfg = DeceptionConfig(interaction_detection_enabled=True)
        detector = DeceptionInteractionDetector(registry=decoy_registry, config=cfg)

        ep = EndpointIdentity(
            endpoint_id="ep-unit-test",
            hostname="HOST",
            platform="Windows",
            os_version="10.0",
            architecture="x64",
        )
        # Event with no context
        event_no_ctx = SecurityEvent(
            event_type=EventType(EventCategory.PROCESS, "CREATE"),
            severity=Severity.INFO,
            source="test",
            endpoint=ep,
        )
        assert detector.analyze_event(event_no_ctx) is None

        # Event with file context having None path
        event_none_path = SecurityEvent(
            event_type=EventType(EventCategory.FILE, "CREATE"),
            severity=Severity.INFO,
            source="test",
            endpoint=ep,
            context=EventContext(file=FileContext(path="", operation="create")),
        )
        assert detector.analyze_event(event_none_path) is None

    def test_is_decoy_and_get_decoy_helpers(self, decoy_registry, temp_dir):
        """is_decoy and get_decoy helper methods operate accurately."""
        detector = DeceptionInteractionDetector(registry=decoy_registry)

        valid_decoy = temp_dir / "credentials" / "passwords.txt"
        assert detector.is_decoy(str(valid_decoy)) is True

        rec = detector.get_decoy(str(valid_decoy))
        assert rec is not None
        assert rec.decoy_id == "decoy-cred-001"

        by_id = detector.get_decoy_by_id("decoy-cred-001")
        assert by_id is not None
        assert by_id.path == rec.path

        non_decoy = temp_dir / "other.txt"
        assert detector.is_decoy(str(non_decoy)) is False
        assert detector.get_decoy(str(non_decoy)) is None
        assert detector.get_decoy_by_id("non-existent") is None

    def test_no_automated_response_or_remediation_taken(self, decoy_registry, temp_dir):
        """Passive detection strictly does not alter files or initiate active defense."""
        detector = DeceptionInteractionDetector(registry=decoy_registry)

        p1 = temp_dir / "credentials" / "passwords.txt"
        original_content = p1.read_text()

        event = make_file_event("MODIFY", str(p1))
        interaction = detector.analyze_event(event)

        assert interaction is not None
        # File should remain intact, unmodified, and not quarantined or deleted
        assert p1.exists()
        assert p1.read_text() == original_content
