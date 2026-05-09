"""Registry for scanner adapters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from packages.adapters.base import BaseAdapter
from packages.adapters.gdpr import GdprAdapter
from packages.adapters.gitleaks import GitleaksAdapter
from packages.adapters.osv import OsvScannerAdapter
from packages.adapters.semgrep import SemgrepAdapter
from packages.adapters.syft import SyftAdapter
from packages.adapters.trivy import TrivyAdapter
from packages.adapters.nuclei import NucleiAdapter
from packages.adapters.zap import ZapAdapter
from packages.core.models import ScanType

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


class AdapterRegistry:
    """
    Registry for scanner adapters.

    Manages adapter instances and provides lookup by scan type.
    """

    # Default adapter classes
    DEFAULT_ADAPTERS: list[type[BaseAdapter]] = [
        GitleaksAdapter,
        SemgrepAdapter,
        TrivyAdapter,
        OsvScannerAdapter,
        NucleiAdapter,
        SyftAdapter,
        ZapAdapter,
        GdprAdapter,
    ]

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the registry.

        Args:
            config: Configuration dictionary with adapter-specific settings
        """
        self.config = config or {}
        self._adapters: dict[str, BaseAdapter] = {}
        self._by_scan_type: dict[ScanType, list[BaseAdapter]] = {st: [] for st in ScanType}

        # Register default adapters
        for adapter_class in self.DEFAULT_ADAPTERS:
            self.register(adapter_class)

    def register(
        self,
        adapter_class: type[BaseAdapter],
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Register an adapter.

        Args:
            adapter_class: The adapter class to register
            config: Optional adapter-specific configuration
        """
        # Get adapter-specific config
        adapter_config = config or self.config.get(adapter_class.name, {})

        # Create instance
        adapter = adapter_class(adapter_config)

        # Store by name
        self._adapters[adapter.name] = adapter

        # Index by scan type
        for scan_type in adapter.scan_types:
            if adapter not in self._by_scan_type[scan_type]:
                self._by_scan_type[scan_type].append(adapter)

        logger.debug(f"Registered adapter: {adapter.name}")

    def get(self, name: str) -> BaseAdapter | None:
        """Get an adapter by name."""
        return self._adapters.get(name)

    def get_for_scan_type(self, scan_type: ScanType) -> list[BaseAdapter]:
        """Get all adapters that support a given scan type."""
        return self._by_scan_type.get(scan_type, [])

    def get_available(self) -> list[BaseAdapter]:
        """Get all adapters that are available (tools installed)."""
        return [adapter for adapter in self._adapters.values() if adapter.is_available()]

    def get_unavailable(self) -> list[BaseAdapter]:
        """Get all adapters that are not available (tools not installed)."""
        return [adapter for adapter in self._adapters.values() if not adapter.is_available()]

    def get_all(self) -> list[BaseAdapter]:
        """Get all registered adapters."""
        return list(self._adapters.values())

    def list_adapters(self) -> list[dict[str, Any]]:
        """
        List all adapters with their status.

        Returns:
            List of adapter info dictionaries
        """
        result = []
        for adapter in self._adapters.values():
            result.append(
                {
                    "name": adapter.name,
                    "tool_name": adapter.tool_name,
                    "scan_types": [st.value for st in adapter.scan_types],
                    "available": adapter.is_available(),
                    "required_binaries": adapter.required_binaries,
                }
            )
        return result

    async def check_availability(self) -> dict[str, dict[str, Any]]:
        """
        Check availability of all adapters and get versions.

        Returns:
            Dictionary mapping adapter names to status info
        """
        result = {}
        for adapter in self._adapters.values():
            available = adapter.is_available()
            version = await adapter.get_version() if available else None
            result[adapter.name] = {
                "available": available,
                "version": version,
                "tool_path": adapter.get_tool_path() if available else None,
            }
        return result

    def get_adapters_for_full_scan(self) -> list[BaseAdapter]:
        """
        Get adapters for a full scan.

        Returns adapters for secrets, deps, SAST, and config scans.
        Web scans are excluded as they require a URL target.
        """
        scan_types = [ScanType.SECRETS, ScanType.DEPS, ScanType.SAST, ScanType.CONFIG]
        adapters = set()

        for scan_type in scan_types:
            for adapter in self.get_for_scan_type(scan_type):
                if adapter.is_available():
                    adapters.add(adapter)

        return list(adapters)

    def get_preferred_adapter(self, scan_type: ScanType) -> BaseAdapter | None:
        """
        Get the preferred (first available) adapter for a scan type.

        Args:
            scan_type: The type of scan

        Returns:
            The preferred adapter or None if none available
        """
        adapters = self.get_for_scan_type(scan_type)
        for adapter in adapters:
            if adapter.is_available():
                return adapter
        return None


# Global registry instance
_registry: AdapterRegistry | None = None


def get_registry(config: dict[str, Any] | None = None) -> AdapterRegistry:
    """Get or create the global adapter registry."""
    global _registry
    if _registry is None:
        _registry = AdapterRegistry(config)
    return _registry


def reset_registry() -> None:
    """Reset the global registry (mainly for testing)."""
    global _registry
    _registry = None
