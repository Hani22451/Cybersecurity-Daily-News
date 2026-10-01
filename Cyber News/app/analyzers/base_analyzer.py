from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.models import IntelligenceItem

class BaseAnalyzer(ABC):
    """Abstract base class for AI/Rule-based intelligence analyzers."""

    @abstractmethod
    def analyze(self, items: List[IntelligenceItem]) -> Dict[str, Any]:
        """
        Analyze a list of intelligence items.
        Returns a dictionary containing executive summary, refined items, defender actions, top 10 items.
        """
        pass
