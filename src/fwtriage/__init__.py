"""Fast, evidence-first security triage for firmware images."""

from fwtriage.app import scan
from fwtriage.model import Confidence, Finding, Policy, Report, Severity
from fwtriage.output.meta import tool_version

__version__ = tool_version()

__all__ = ["Confidence", "Finding", "Policy", "Report", "Severity", "__version__", "scan"]
