from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional

@dataclass
class IntelligenceItem:
    id: str
    title: str
    summary: str
    content: str
    published_at: datetime
    source_name: str
    source_url: str
    corroborating_sources: List[Dict[str, str]] = field(default_factory=list)
    
    category: str = "OTHER"
    priority: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_explanation: str = ""
    
    cves: List[Dict[str, any]] = field(default_factory=list)
    threat_actor: Optional[Dict[str, str]] = None
    data_breach: Optional[Dict[str, str]] = None
    malware_info: Optional[Dict[str, str]] = None
    
    defensive_actions: List[str] = field(default_factory=list)
    is_verified: bool = True
    verification_note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "content": self.content,
            "published_at": self.published_at.isoformat(),
            "source_name": self.source_name,
            "source_url": self.source_url,
            "corroborating_sources": self.corroborating_sources,
            "category": self.category,
            "priority": self.priority,
            "risk_explanation": self.risk_explanation,
            "cves": self.cves,
            "threat_actor": self.threat_actor,
            "data_breach": self.data_breach,
            "malware_info": self.malware_info,
            "defensive_actions": self.defensive_actions,
            "is_verified": self.is_verified,
            "verification_note": self.verification_note,
        }
