"""Configuration management for SecScan."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class ScanSettings(BaseModel):
    """Scan-related settings."""

    types: list[str] = Field(default=["secrets", "deps", "sast", "config"])
    severity_threshold: str = Field(default="info")
    fail_on_severity: str | None = Field(default="high")
    timeout: int = Field(default=3600)
    max_findings: int | None = Field(default=None)
    generate_patches: bool = Field(default=True)
    exclude: list[str] = Field(
        default=[
            "**/node_modules/**",
            "**/venv/**",
            "**/.git/**",
            "**/dist/**",
            "**/build/**",
        ]
    )


class GitleaksSettings(BaseModel):
    """Gitleaks-specific settings."""

    config_path: str | None = Field(default=None)
    baseline_path: str | None = Field(default=None)


class SemgrepSettings(BaseModel):
    """Semgrep-specific settings."""

    rulesets: list[str] = Field(default=["auto"])
    exclude: list[str] = Field(default=[])


class TrivySettings(BaseModel):
    """Trivy-specific settings."""

    severity: str = Field(default="UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")
    scanners: list[str] = Field(default=["vuln", "misconfig", "secret"])
    skip_update: bool = Field(default=False)


class ZapSettings(BaseModel):
    """ZAP-specific settings."""

    minutes: int = Field(default=1)
    ajax_spider: bool = Field(default=False)
    rules_file: str | None = Field(default=None)


class ToolSettings(BaseModel):
    """Tool-specific settings container."""

    gitleaks: GitleaksSettings = Field(default_factory=GitleaksSettings)
    semgrep: SemgrepSettings = Field(default_factory=SemgrepSettings)
    trivy: TrivySettings = Field(default_factory=TrivySettings)
    zap: ZapSettings = Field(default_factory=ZapSettings)


class StorageSettings(BaseModel):
    """Storage settings."""

    database_url: str = Field(default="sqlite+aiosqlite:///secscan.db")


class ApiSettings(BaseModel):
    """API settings."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    cors_origins: list[str] = Field(default=["*"])


class LoggingSettings(BaseModel):
    """Logging settings."""

    level: str = Field(default="INFO")
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


class Settings(BaseSettings):
    """Main settings class."""

    scan: ScanSettings = Field(default_factory=ScanSettings)
    tools: ToolSettings = Field(default_factory=ToolSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    api: ApiSettings = Field(default_factory=ApiSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    class Config:
        env_prefix = "SECSCAN_"
        env_nested_delimiter = "__"


def load_config(config_path: Path | str | None = None) -> Settings:
    """
    Load configuration from file and environment.

    Priority (highest to lowest):
    1. Environment variables
    2. Config file
    3. Default values

    Args:
        config_path: Path to config file. If None, searches for:
            - .secscan.yaml in current directory
            - configs/default.yaml in package directory

    Returns:
        Settings object
    """
    config_data: dict[str, Any] = {}

    # Find config file
    if config_path is None:
        # Check current directory
        local_config = Path(".secscan.yaml")
        if local_config.exists():
            config_path = local_config
        else:
            # Check package configs directory
            package_config = Path(__file__).parent.parent.parent / "configs" / "default.yaml"
            if package_config.exists():
                config_path = package_config

    # Load config file
    if config_path:
        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f) or {}

    # Create settings (environment variables will override)
    return Settings(**config_data)


def get_adapter_config(settings: Settings, adapter_name: str) -> dict[str, Any]:
    """
    Get configuration for a specific adapter.

    Args:
        settings: Settings object
        adapter_name: Name of the adapter (e.g., 'gitleaks', 'semgrep')

    Returns:
        Configuration dictionary for the adapter
    """
    tool_settings = getattr(settings.tools, adapter_name, None)
    if tool_settings:
        return tool_settings.model_dump()
    return {}


# Global settings instance
_settings: Settings | None = None


def get_settings(config_path: Path | str | None = None) -> Settings:
    """Get or create the global settings instance."""
    global _settings
    if _settings is None:
        _settings = load_config(config_path)
    return _settings


def reset_settings() -> None:
    """Reset the global settings instance (for testing)."""
    global _settings
    _settings = None
