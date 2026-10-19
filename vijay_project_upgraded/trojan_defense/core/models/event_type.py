"""Canonical event type mechanism for security telemetry.

Defines the core categories supported by the framework without embedding
detection logic or specific Trojan classification rules.
"""

from enum import Enum


class EventCategory(str, Enum):
    """High-level categories for telemetry and cyber deception events."""
    PROCESS = "PROCESS"
    FILE = "FILE"
    NETWORK = "NETWORK"
    SYSTEM = "SYSTEM"
    PRIVILEGE = "PRIVILEGE"
    DECEPTION = "DECEPTION"
    BEHAVIOR = "BEHAVIOR"


class EventType:
    """Represents a canonical event type with category and optional action.

    Examples:
        EventType("PROCESS", "CREATE")
        EventType.from_string("PROCESS.CREATE")
        EventType.from_category(EventCategory.FILE)
    """

    def __init__(self, category: str | EventCategory, action: str | None = None) -> None:
        if isinstance(category, EventCategory):
            self._category = category
        else:
            cat_upper = str(category).strip().upper()
            try:
                self._category = EventCategory(cat_upper)
            except ValueError as exc:
                valid = [c.value for c in EventCategory]
                raise ValueError(
                    f"Invalid event category '{cat_upper}'. Must be one of: {valid}"
                ) from exc

        self._action = action.strip().upper() if action else None

    @property
    def category(self) -> EventCategory:
        """The high-level category of the event."""
        return self._category

    @property
    def action(self) -> str | None:
        """The specific action or sub-type, if provided."""
        return self._action

    @property
    def value(self) -> str:
        """String representation of the event type (e.g., 'PROCESS' or 'PROCESS.CREATE')."""
        if self._action:
            return f"{self._category.value}.{self._action}"
        return self._category.value

    @classmethod
    def from_string(cls, value: str) -> "EventType":
        """Parse an event type string such as 'PROCESS' or 'PROCESS.CREATE'."""
        if not value or not isinstance(value, str):
            raise ValueError("Event type string cannot be empty")
        parts = value.strip().split(".", 1)
        category = parts[0]
        action = parts[1] if len(parts) > 1 else None
        return cls(category=category, action=action)

    @classmethod
    def with_action(cls, category: EventCategory | str, action: str) -> "EventType":
        """Create an EventType with a specific category and action."""
        return cls(category=category, action=action)

    @classmethod
    def from_category(cls, category: EventCategory) -> "EventType":
        """Create an EventType directly from an EventCategory enum."""
        return cls(category=category)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"EventType('{self.value}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, EventType):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other.strip().upper()
        if isinstance(other, EventCategory):
            return self._category == other and self._action is None
        return False

    def __hash__(self) -> int:
        return hash(self.value)
