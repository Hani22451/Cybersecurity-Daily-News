from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from app.models import IntelligenceItem
from app.utils.logger import logger

class MarkdownReporter:
    """Generates structured Markdown reports following defensive security standards."""

    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, analysis_data: Dict[str, Any], target_filename: str = None) -> tuple[str, Path]:
        now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        filename = target_filename or f"{now_date}.md"
        filepath = self.output_dir / filename

        items: List[IntelligenceItem] = analysis_data.get("refined_items", [])
        exec_summary = analysis_data.get("executive_summary", [])
        defender_actions = analysis_data.get("defender_actions", {})
        top_10 = analysis_data.get("top_10", [])

        # Categorize items for specialized sections
        critical_items = [i for i in items if i.priority in ["CRITICAL", "HIGH"]]
        vuln_items = [i for i in items if i.cves or "VULNERABILITY" in i.category]
        malware_items = [i for i in items if i.category in ["MALWARE", "RANSOMWARE"]]
        apt_items = [i for i in items if i.category == "APT / THREAT ACTOR"]
        breach_items = [i for i in items if i.category == "DATA BREACH"]
        ai_items = [i for i in items if i.category == "AI SECURITY"]

        md_lines = []

        # Title & Header
        md_lines.append("# CYBERSECURITY DAILY INTELLIGENCE REPORT")
        md_lines.append("")
        md_lines.append(f"**Date:** {now_date}")
        md_lines.append("")

        # 1. Executive Summary
        md_lines.append("## Executive Summary")
        md_lines.append("")
        if exec_summary:
            for bullet in exec_summary:
                md_lines.append(f"* {bullet}")
        else:
            md_lines.append("* No major high-severity developments reported in the last 24 hours.")
        md_lines.append("")

        # 2. Critical Security Developments
        md_lines.append("## 🔴 Critical Security Developments")
        md_lines.append("")
        if critical_items:
            for item in critical_items[:6]:
                md_lines.append(f"### {item.title}")
                md_lines.append(f"**Category:** {item.category}")
                md_lines.append(f"**Priority:** {item.priority}")
                md_lines.append(f"**Published:** {item.published_at.strftime('%Y-%m-%d %H:%M UTC')}")
                affected_prod = item.cves[0].get('product', 'Various systems') if item.cves else 'See details'
                md_lines.append(f"**Affected:** {affected_prod}")
                md_lines.append("")
                md_lines.append("**What happened:**")
                md_lines.append(f"{item.summary}")
                md_lines.append("")
                md_lines.append("**Why it matters:**")
                md_lines.append(f"{item.risk_explanation or 'May allow unauthorized system access or data exposure.'}")
                md_lines.append("")
                md_lines.append("**What defenders should do:**")
                for act in item.defensive_actions:
                    md_lines.append(f"* {act}")
                md_lines.append("")
                md_lines.append("**Sources:**")
                md_lines.append(f"* {item.source_name} — {item.source_url}")
                for corr in item.corroborating_sources:
                    md_lines.append(f"* {corr['name']} — {corr['url']}")
                md_lines.append("")
                md_lines.append("---")
                md_lines.append("")
        else:
            md_lines.append("No critical security developments reported today.")
            md_lines.append("")

        # 3. Vulnerability Intelligence Table
        md_lines.append("## 🔐 Vulnerability Intelligence")
        md_lines.append("")
        md_lines.append("| CVE | Product | Severity | CVSS | Exploited? | KEV? | Patch Available? |")
        md_lines.append("| --- | ------- | -------- | ---- | ---------- | ---- | ---------------- |")

        cve_rows_count = 0
        for item in vuln_items:
            for cve in item.cves:
                cve_id = cve.get("id", "CVE-Unknown")
                product = cve.get("product", item.title[:30])
                sev = cve.get("severity", item.priority)
                cvss = cve.get("cvss", "N/A")
                exploited = "Yes ⚠️" if cve.get("exploited", False) else "No"
                kev = "Yes 🔴" if cve.get("kev", False) else "No"
                patch = "Yes" if cve.get("patch_available", True) else "Pending"

                md_lines.append(f"| [{cve_id}]({item.source_url}) | {product} | {sev} | {cvss} | {exploited} | {kev} | {patch} |")
                cve_rows_count += 1

        if cve_rows_count == 0:
            md_lines.append("| N/A | None reported in window | N/A | N/A | No | No | N/A |")
        md_lines.append("")

        # 4. Malware & Ransomware
        md_lines.append("## 🦠 Malware & Ransomware")
        md_lines.append("")
        if malware_items:
            for item in malware_items:
                md_lines.append(f"### {item.title}")
                md_lines.append(f"* **Category:** {item.category}")
                md_lines.append(f"* **Impact:** {item.summary[:250]}")
                md_lines.append(f"* **Defensive Actions:** {', '.join(item.defensive_actions)}")
                md_lines.append(f"* **Source:** [{item.source_name}]({item.source_url})")
                md_lines.append("")
        else:
            md_lines.append("No major malware or ransomware campaigns reported in this period.")
            md_lines.append("")

        # 5. Threat Actors / APT
        md_lines.append("## 🎯 Threat Actors / APT")
        md_lines.append("")
        if apt_items:
            for item in apt_items:
                md_lines.append(f"### {item.title}")
                md_lines.append(f"* **Summary:** {item.summary}")
                md_lines.append(f"* **Attribution Status:** Reported by {item.source_name} (Not independently verified)")
                md_lines.append(f"* **Source:** [{item.source_name}]({item.source_url})")
                md_lines.append("")
        else:
            md_lines.append("No specific nation-state or APT campaign reports in this period.")
            md_lines.append("")

        # 6. Data Breaches
        md_lines.append("## 🔓 Data Breaches")
        md_lines.append("")
        if breach_items:
            for item in breach_items:
                md_lines.append(f"### {item.title}")
                md_lines.append(f"* **Summary:** {item.summary}")
                md_lines.append(f"* **Source:** [{item.source_name}]({item.source_url})")
                md_lines.append("")
        else:
            md_lines.append("No major confirmed data breaches reported in this period.")
            md_lines.append("")

        # 7. AI Security
        md_lines.append("## 🤖 AI Security")
        md_lines.append("")
        if ai_items:
            for item in ai_items:
                md_lines.append(f"### {item.title}")
                md_lines.append(f"* **Summary:** {item.summary}")
                md_lines.append(f"* **Source:** [{item.source_name}]({item.source_url})")
                md_lines.append("")
        else:
            md_lines.append("No significant AI security incidents or research reported in this period.")
            md_lines.append("")

        # 8. Defender Action Items
        md_lines.append("## 🛡️ Defender Action Items")
        md_lines.append("")
        md_lines.append("### Immediate")
        for act in defender_actions.get("immediate", []):
            md_lines.append(f"* [ ] {act}")
        md_lines.append("")

        md_lines.append("### This Week")
        for act in defender_actions.get("this_week", []):
            md_lines.append(f"* [ ] {act}")
        md_lines.append("")

        md_lines.append("### Monitor")
        for act in defender_actions.get("monitor", []):
            md_lines.append(f"* [ ] {act}")
        md_lines.append("")

        # 9. Top 10 Items by Reporting Relevance
        md_lines.append("## 📌 Top 10 Items")
        md_lines.append("")
        md_lines.append("*Top 10 developments by reporting relevance & defensive priority:*")
        md_lines.append("")
        for idx, item in enumerate(top_10[:10], start=1):
            md_lines.append(f"{idx}. [{item.priority}] **{item.title}** ({item.source_name}) — [Link]({item.source_url})")
        md_lines.append("")

        # 10. Sources
        md_lines.append("## 📚 Sources")
        md_lines.append("")
        source_map = {}
        for item in items:
            source_map[item.source_url] = item.source_name
            for corr in item.corroborating_sources:
                source_map[corr["url"]] = corr["name"]

        for url, name in source_map.items():
            md_lines.append(f"* **{name}**: {url}")
        md_lines.append("")

        full_content = "\n".join(md_lines)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(full_content)
            logger.info(f"Successfully generated Markdown report at {filepath}")
        except Exception as e:
            logger.error(f"Failed to write report file: {e}")

        return full_content, filepath
