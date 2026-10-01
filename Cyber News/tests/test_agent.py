import unittest
from datetime import datetime, timezone
from app.models import IntelligenceItem
from app.processors.deduplicator import Deduplicator, text_similarity
from app.processors.categorizer import Categorizer
from app.utils.helpers import extract_cves, clean_html, parse_datetime

class TestCyberAgent(unittest.TestCase):

    def test_helpers(self):
        cves = extract_cves("Check CVE-2024-1234 and CVE-2023-99999 for details.")
        self.assertEqual(cves, ["CVE-2023-99999", "CVE-2024-1234"])
        
        raw_html = "<p>Critical <b>Ransomware</b> attack &amp; data breach!</p>"
        cleaned = clean_html(raw_html)
        self.assertEqual(cleaned, "Critical Ransomware attack & data breach!")

    def test_deduplicator(self):
        item1 = IntelligenceItem(
            id="1",
            title="Critical Flaw in Windows Kernel Allowed Remote Code Execution",
            summary="Microsoft fixed a flaw",
            content="",
            published_at=datetime.now(timezone.utc),
            source_name="BleepingComputer",
            source_url="https://example.com/1",
            cves=[{"id": "CVE-2024-5555"}]
        )
        item2 = IntelligenceItem(
            id="2",
            title="Windows Kernel Vulnerability CVE-2024-5555 Enables RCE Attacks",
            summary="Security advisory regarding kernel flaw",
            content="",
            published_at=datetime.now(timezone.utc),
            source_name="SecurityWeek",
            source_url="https://example.com/2",
            cves=[{"id": "CVE-2024-5555"}]
        )

        dedup = Deduplicator()
        unique = dedup.deduplicate([item1, item2])
        self.assertEqual(len(unique), 1)
        self.assertEqual(len(unique[0].corroborating_sources), 1)

    def test_categorizer(self):
        item = IntelligenceItem(
            id="1",
            title="LockBit Ransomware Extorts Major Healthcare Provider",
            summary="Data stolen in recent incident",
            content="",
            published_at=datetime.now(timezone.utc),
            source_name="News",
            source_url="https://example.com"
        )
        categorizer = Categorizer()
        categorizer.categorize_item(item)
        self.assertEqual(item.category, "RANSOMWARE")
        self.assertEqual(item.priority, "HIGH")

if __name__ == "__main__":
    unittest.main()
