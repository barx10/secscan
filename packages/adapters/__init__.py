"""Scanner adapters package."""

from packages.adapters.base import BaseAdapter, AdapterResult
from packages.adapters.gitleaks import GitleaksAdapter
from packages.adapters.gdpr import GdprAdapter
from packages.adapters.semgrep import SemgrepAdapter
from packages.adapters.trivy import TrivyAdapter
from packages.adapters.osv import OsvScannerAdapter
from packages.adapters.zap import ZapAdapter
from packages.adapters.syft import SyftAdapter
from packages.adapters.registry import AdapterRegistry

__all__ = [
    "BaseAdapter",
    "AdapterResult",
    "GitleaksAdapter",
    "GdprAdapter",
    "SemgrepAdapter",
    "TrivyAdapter",
    "OsvScannerAdapter",
    "ZapAdapter",
    "SyftAdapter",
    "AdapterRegistry",
]
