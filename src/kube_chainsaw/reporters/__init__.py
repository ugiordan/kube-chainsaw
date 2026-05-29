"""Reporter base class and implementations."""

from abc import ABC, abstractmethod
from typing import List

from kube_chainsaw.models import Finding


class Reporter(ABC):
    """Base class for all reporters."""

    @abstractmethod
    def render(self, findings: List[Finding]) -> str:
        """Render findings to output format.

        Args:
            findings: List of findings to render.

        Returns:
            Formatted output string.
        """
        ...


__all__ = ["Reporter"]
