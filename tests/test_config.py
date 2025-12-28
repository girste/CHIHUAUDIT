"""Test configuration loading."""

import json
import tempfile
from pathlib import Path
from mcp_security.utils.config import load_config, DEFAULT_CONFIG


def test_default_config():
    """Test that default config is returned when no file exists."""
    config = load_config()
    assert config == DEFAULT_CONFIG


def test_custom_config():
    """Test loading custom config from file."""
    custom_config = {
        "checks": {
            "firewall": True,
            "ssh": False,
            "docker": False,
        },
        "threat_analysis_days": 14,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(custom_config, f)
        config_path = Path(f.name)

    try:
        import os

        old_cwd = os.getcwd()
        os.chdir(config_path.parent)

        config_path.rename(config_path.parent / ".mcp-security.json")
        config = load_config()

        assert config["threat_analysis_days"] == 14
        assert not config["checks"]["ssh"]

    finally:
        os.chdir(old_cwd)
        (config_path.parent / ".mcp-security.json").unlink(missing_ok=True)
