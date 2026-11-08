"""EDR prototype package."""

from .client import EDRClient
from .collector import collect_snapshot
from .ioc import detect_ioc

__all__ = ["EDRClient", "collect_snapshot", "detect_ioc"]
