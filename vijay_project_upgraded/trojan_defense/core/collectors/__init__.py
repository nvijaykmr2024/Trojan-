"""Collector subsystem for the Trojan Defense framework."""

from trojan_defense.core.collectors.base import BaseCollector, CollectorStatus
from trojan_defense.core.collectors.registry import CollectorRegistry

__all__ = ["BaseCollector", "CollectorRegistry", "CollectorStatus"]
