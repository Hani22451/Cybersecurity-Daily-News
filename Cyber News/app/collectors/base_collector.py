from abc import ABC, abstractmethod
from typing import List
from app.models import IntelligenceItem

class BaseCollector(ABC):
    """Abstract base class for all cybersecurity data collectors."""

    @abstractmethod
    def fetch_items(self, hours_lookback: int = 24, max_items: int = 50) -> List[IntelligenceItem]:
        """Fetch items published within the specified lookback window."""
        pass
