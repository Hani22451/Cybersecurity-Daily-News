import re
from typing import List
from app.models import IntelligenceItem
from app.utils.logger import logger

CATEGORY_RULES = {
    "ZERO-DAY": [r"zero-day", r"0-day", r"unpatched", r"zero day"],
    "EXPLOITED VULNERABILITY": [r"actively exploited", r"cisa kev", r"exploited in the wild", r"in-the-wild"],
    "CRITICAL VULNERABILITY": [r"critical vulnerability", r"cvss 10", r"cvss 9\.", r"remote code execution", r"rce"],
    "HIGH-RISK VULNERABILITY": [r"high severity", r"privilege escalation", r"bypass", r"vulnerability"],
    "RANSOMWARE": [r"ransomware", r"lockbit", r"blackcat", r"alphv", r"clop", r"rhysida", r"extortion", r"ransom"],
    "MALWARE": [r"trojan", r"botnet", r"infostealer", r"malware", r"spyware", r"loader", r"backdoor", r"stealer"],
    "PHISHING": [r"phishing", r"spear-phishing", r"credential stuffing", r"social engineering", r"smishing"],
    "DATA BREACH": [r"data breach", r"leak", r"stolen records", r"database exposed", r"hacked database", r"compromised records"],
    "APT / THREAT ACTOR": [r"apt", r"lazarus", r"fancy bear", r"volt typhoon", r"cozy bear", r"threat actor", r"nation-state"],
    "AI SECURITY": [r"ai security", r"chatgpt", r"llm", r"prompt injection", r"copilot", r"artificial intelligence", r"deepseek"],
    "CLOUD SECURITY": [r"aws", r"azure", r"gcp", r"cloud security", r"s3 bucket", r"kubernetes", r"cloud incident"],
    "APPLICATION SECURITY": [r"web app", r"sql injection", r"xss", r"api security", r"csrf"],
    "NETWORK SECURITY": [r"ddos", r"router", r"vpn", r"firewall", r"cisco", r"fortinet", r"palo alto"],
    "MOBILE SECURITY": [r"android", r"ios", r"mobile app", r"google play", r"app store"],
    "IDENTITY SECURITY": [r"active directory", r"okta", r"iam", r"mfa", r"authentication", r"passkeys", r"oauth"],
    "SECURITY RESEARCH": [r"proof of concept", r"poc", r"security research", r"researcher", r"advisory"],
    "PATCH / SECURITY ADVISORY": [r"patch Tuesday", r"security update", r"security advisory", r"fix released"]
}

class Categorizer:
    """Classifies items and calculates initial priority score."""

    def categorize_item(self, item: IntelligenceItem) -> IntelligenceItem:
        text = f"{item.title} {item.summary} {item.content}".lower()

        # Check for KEV / exploited status first
        if any(cve.get("kev", False) for cve in item.cves) or "actively exploited" in text:
            item.category = "EXPLOITED VULNERABILITY"
            item.priority = "CRITICAL"
            item.risk_explanation = "Actively exploited vulnerability reported by authoritative sources."
            return item

        # Match category rules
        assigned_category = None
        for cat, patterns in CATEGORY_RULES.items():
            if any(re.search(p, text) for p in patterns):
                assigned_category = cat
                break

        if assigned_category:
            item.category = assigned_category

        # Determine Priority
        if item.category in ["CRITICAL VULNERABILITY", "EXPLOITED VULNERABILITY", "ZERO-DAY"]:
            item.priority = "CRITICAL"
            item.risk_explanation = "High-impact exploit or critical vulnerability requiring immediate attention."
        elif item.category in ["RANSOMWARE", "DATA BREACH", "APT / THREAT ACTOR", "HIGH-RISK VULNERABILITY"]:
            item.priority = "HIGH"
            item.risk_explanation = "Active malware campaign or major incident impacting organizational security."
        elif item.category in ["MALWARE", "PHISHING", "CLOUD SECURITY", "AI SECURITY"]:
            item.priority = "MEDIUM"
            item.risk_explanation = "Notable security event or threat pattern."
        else:
            item.priority = "LOW"
            item.risk_explanation = "General security news or advisory."

        return item

    def process_all(self, items: List[IntelligenceItem]) -> List[IntelligenceItem]:
        logger.info(f"Categorizing {len(items)} items...")
        for item in items:
            self.categorize_item(item)
        return items
