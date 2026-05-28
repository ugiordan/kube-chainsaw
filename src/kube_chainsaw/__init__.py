"""kube-chainsaw: Graph-level RBAC privilege chain analysis for Kubernetes manifests."""

from kube_chainsaw.analyzer import RBACAnalyzer
from kube_chainsaw.models import AnalyzerError, Finding, Severity

__version__ = "0.1.0"
__all__ = ["AnalyzerError", "Finding", "RBACAnalyzer", "Severity", "__version__"]
