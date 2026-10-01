from typing import List, Dict, Any
from app.analyzers.base_analyzer import BaseAnalyzer
from app.models import IntelligenceItem
from app.utils.logger import logger

class FallbackAnalyzer(BaseAnalyzer):
    """Zero-cost offline analyzer using rule-based extraction and heuristics."""

    def analyze(self, items: List[IntelligenceItem]) -> Dict[str, Any]:
        logger.info(f"Running Fallback Rule-Based Analyzer on {len(items)} items (Offline / Free)...")

        # Sort items by priority: CRITICAL > HIGH > MEDIUM > LOW > INFO
        priority_weights = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        sorted_items = sorted(items, key=lambda x: priority_weights.get(x.priority, 1), reverse=True)

        # 1. Executive Summary
        executive_summary = []
        for item in sorted_items[:8]:
            cve_str = f" ({', '.join([c['id'] for c in item.cves])})" if item.cves else ""
            executive_summary.append(f"**[{item.category}]** {item.title}{cve_str}: {item.summary[:200]}")

        # 2. Refine item defensive recommendations & risk explanation
        for item in sorted_items:
            if not item.defensive_actions:
                if item.category in ["CRITICAL VULNERABILITY", "EXPLOITED VULNERABILITY", "ZERO-DAY"]:
                    item.defensive_actions = [
                        "Apply vendor security patches immediately.",
                        "Audit network logs for potential exploitation indicators.",
                        "Restrict access to vulnerable interfaces via firewalls or VPNs."
                    ]
                elif item.category in ["RANSOMWARE", "MALWARE"]:
                    item.defensive_actions = [
                        "Ensure offline backups are updated and verified.",
                        "Review EDR / antivirus alerts for unauthorized process execution.",
                        "Enforce strict email filtering and user awareness training."
                    ]
                elif item.category == "DATA BREACH":
                    item.defensive_actions = [
                        "Enforce credential resets for affected accounts.",
                        "Enable multi-factor authentication (MFA) across all remote access points.",
                        "Monitor dark web channels for leaked corporate credentials."
                    ]
                else:
                    item.defensive_actions = [
                        "Monitor vendor advisories for updates.",
                        "Maintain principle of least privilege across cloud and local accounts."
                    ]

            if not item.risk_explanation:
                item.risk_explanation = f"Poses risk under category '{item.category}' based on reporting from {item.source_name}."

        # 3. Categorized Action Items
        immediate_actions = []
        this_week_actions = []
        monitor_items = []

        for item in sorted_items:
            cve_name = item.cves[0]['id'] if item.cves else item.title[:40]
            if item.priority == "CRITICAL":
                immediate_actions.append(f"Patch / mitigate {cve_name} ({item.source_name})")
            elif item.priority == "HIGH":
                this_week_actions.append(f"Audit systems for exposure to {cve_name}")
            else:
                monitor_items.append(f"Track developments on {item.title[:60]}")

        defender_actions = {
            "immediate": list(set(immediate_actions))[:5] or ["Apply pending critical OS and software updates."],
            "this_week": list(set(this_week_actions))[:5] or ["Review asset inventory and vulnerability scan results."],
            "monitor": list(set(monitor_items))[:5] or ["Monitor CISA KEV and vendor security advisories."]
        }

        # 4. Top 10 items
        top_10 = sorted_items[:10]

        return {
            "executive_summary": executive_summary,
            "refined_items": sorted_items,
            "defender_actions": defender_actions,
            "top_10": top_10
        }
