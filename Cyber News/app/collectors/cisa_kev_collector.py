import hashlib
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Dict
from app.collectors.base_collector import BaseCollector
from app.models import IntelligenceItem
from app.utils.helpers import parse_datetime
from app.utils.logger import logger

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "CyberDailyIntelAgent/1.0 (+https://github.com/cybersecurity-news-automation)"

class CISAKEVCollector(BaseCollector):
    """Collects newly added Known Exploited Vulnerabilities from CISA KEV Feed."""

    def __init__(self, url: str = CISA_KEV_URL):
        self.url = url

    def fetch_items(self, hours_lookback: int = 24, max_items: int = 50) -> List[IntelligenceItem]:
        items: List[IntelligenceItem] = []
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=hours_lookback)

        logger.info(f"Fetching CISA KEV feed from {self.url}")

        try:
            res = requests.get(self.url, headers={"User-Agent": USER_AGENT}, timeout=5)
            if res.status_code != 200:
                logger.warning(f"Failed to fetch CISA KEV feed: HTTP {res.status_code}")
                return items

            data = res.json()
            vulnerabilities = data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                date_added_str = vuln.get("dateAdded", "")
                date_added = parse_datetime(date_added_str)

                # Filter by lookback window
                if date_added < cutoff_time:
                    continue

                cve_id = vuln.get("cveID", "")
                vendor = vuln.get("vendorProject", "")
                product = vuln.get("product", "")
                vulnerability_name = vuln.get("vulnerabilityName", "")
                short_desc = vuln.get("shortDescription", "")
                required_action = vuln.get("requiredAction", "")
                due_date = vuln.get("dueDate", "")
                notes = vuln.get("notes", "")

                title = f"CISA KEV ALERT: {cve_id} in {vendor} {product} - {vulnerability_name}"
                item_id = hashlib.md5(f"cisa_kev_{cve_id}".encode('utf-8')).hexdigest()

                cve_details = [{
                    "id": cve_id,
                    "product": f"{vendor} {product}",
                    "severity": "CRITICAL",
                    "cvss": "N/A",
                    "exploited": True,
                    "kev": True,
                    "patch_available": True,
                    "required_action": required_action,
                    "due_date": due_date,
                    "source": "CISA KEV Catalog"
                }]

                intel_item = IntelligenceItem(
                    id=item_id,
                    title=title,
                    summary=short_desc,
                    content=f"{short_desc}\n\nRequired Action: {required_action}\nDue Date: {due_date}\nNotes: {notes}",
                    published_at=date_added,
                    source_name="CISA KEV Catalog",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    category="EXPLOITED VULNERABILITY",
                    priority="CRITICAL",
                    risk_explanation="Vulnerability is actively exploited in the wild and listed on the CISA KEV catalog.",
                    cves=cve_details,
                    defensive_actions=[required_action] if required_action else []
                )

                items.append(intel_item)
                if len(items) >= max_items:
                    break

            logger.info(f"Collected {len(items)} fresh CISA KEV items")

        except Exception as e:
            logger.error(f"Error fetching CISA KEV catalog: {e}")

        return items
