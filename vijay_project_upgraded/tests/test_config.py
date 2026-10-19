"""Tests for the Configuration subsystem."""

import json
from pathlib import Path
import pytest

from trojan_defense.core.config.loader import load_config, validate_config
from trojan_defense.core.config.schema import RootConfig
from trojan_defense.core.exceptions import ConfigurationError


class TestConfig:
    def test_default_config_loads_with_valid_defaults(self):
        config = RootConfig()
        validate_config(config)
        assert config.app.environment == "development"
        assert config.app.debug is False
        assert config.logging.level == "INFO"
        assert config.pipeline.batch_size == 50
        assert config.persistence.enabled is True
        assert config.persistence.driver == "sqlite"
        assert config.transport.driver == "mock"

    def test_load_config_with_explicit_file(self, tmp_path: Path):
        custom_file = tmp_path / "custom_config.json"
        data = {
            "app": {"environment": "production", "debug": False},
            "logging": {"level": "WARNING"},
            "pipeline": {"batch_size": 100},
            "persistence": {"driver": "memory"},
        }
        custom_file.write_text(json.dumps(data), encoding="utf-8")

        config = load_config(config_file=custom_file)
        assert config.app.environment == "production"
        assert config.logging.level == "WARNING"
        assert config.pipeline.batch_size == 100
        assert config.persistence.driver == "memory"

    def test_load_config_missing_file_raises_error(self):
        with pytest.raises(ConfigurationError, match="Specified configuration file not found"):
            load_config(config_file="non_existent_file.json")

    def test_load_config_malformed_json_raises_error(self, tmp_path: Path):
        bad_file = tmp_path / "malformed.json"
        bad_file.write_text("{bad json: true", encoding="utf-8")

        with pytest.raises(ConfigurationError, match="Malformed JSON"):
            load_config(config_file=bad_file)

    def test_invalid_environment_raises_error(self):
        config = RootConfig()
        config.app.environment = "invalid_env"
        with pytest.raises(ConfigurationError, match="Invalid environment"):
            validate_config(config)

    def test_invalid_log_level_raises_error(self):
        config = RootConfig()
        config.logging.level = "VERBOSE"
        with pytest.raises(ConfigurationError, match="Invalid log level"):
            validate_config(config)

    def test_invalid_batch_size_raises_error(self):
        config = RootConfig()
        config.pipeline.batch_size = -5
        with pytest.raises(ConfigurationError, match="batch_size must be positive"):
            validate_config(config)

    def test_invalid_persistence_driver_raises_error(self):
        config = RootConfig()
        config.persistence.driver = "postgres"
        with pytest.raises(ConfigurationError, match="Invalid persistence driver"):
            validate_config(config)

    def test_invalid_transport_driver_raises_error(self):
        config = RootConfig()
        config.transport.driver = "kafka"
        with pytest.raises(ConfigurationError, match="Invalid transport driver"):
            validate_config(config)

    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("TROJAN_DEFENSE_ENV", "test")
        monkeypatch.setenv("TROJAN_DEFENSE_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("TROJAN_DEFENSE_PIPELINE_BATCH_SIZE", "25")
        monkeypatch.setenv("TROJAN_DEFENSE_PERSISTENCE_ENABLED", "false")

        config = load_config()
        assert config.app.environment == "test"
        assert config.logging.level == "DEBUG"
        assert config.pipeline.batch_size == 25
        assert config.persistence.enabled is False
