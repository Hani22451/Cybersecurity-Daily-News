import hashlib
import feedparser
import requests
from datetime import datetime, timezone, timedelta
from typing import List, Dict
from app.collectors.base_collector import BaseCollector
from app.models import IntelligenceItem
from app.utils.helpers import parse_datetime, clean_html, extract_cves
from app.utils.logger import logger

USER_AGENT = "CyberDailyIntelAgent/1.0 (+https://github.com/cybersecurity-news-automation)"

class RSSCollector(BaseCollector):
    """Collects security intelligence from RSS / Atom feeds."""

    def __init__(self, feeds: List[Dict[str, str]]):
        self.feeds = feeds

    def fetch_items(self, hours_lookback: int = 24, max_items: int = 50) -> List[IntelligenceItem]:
        items: List[IntelligenceItem] = []
        now = datetime.now(timezone.utc)
        cutoff_time = now - timedelta(hours=hours_lookback)

        for feed_info in self.feeds:
            if not feed_info.get("enabled", True):
                continue

            feed_name = feed_info.get("name", "RSS Feed")
            feed_url = feed_info.get("url", "")
            category_hint = feed_info.get("category_hint", "OTHER")

            if not feed_url:
                continue

            logger.info(f"Fetching RSS feed: {feed_name} ({feed_url})")

            try:
                # Fetch raw content with custom headers to avoid bot blocks
                response = requests.get(feed_url, headers={"User-Agent": USER_AGENT}, timeout=5)
                if response.status_code != 200:
                    logger.warning(f"Failed to fetch {feed_name}: HTTP status {response.status_code}")
                    continue

                parsed = feedparser.parse(response.content)
                count = 0

                for entry in parsed.entries[:max_items]:
                    title = clean_html(getattr(entry, 'title', 'No Title'))
                    link = getattr(entry, 'link', '')
                    summary_raw = getattr(entry, 'summary', '') or getattr(entry, 'description', '')
                    content_raw = ""
                    if 'content' in entry and len(entry.content) > 0:
                        content_raw = entry.content[0].value

                    summary = clean_html(summary_raw)
                    content = clean_html(content_raw) or summary

                    # Parse publication date
                    pub_date_str = getattr(entry, 'published', None) or getattr(entry, 'updated', None)
                    pub_date = parse_datetime(pub_date_str)

                    # Freshness filter
                    if pub_date < cutoff_time:
                        continue

                    item_id = hashlib.md5(f"{link}{title}".encode('utf-8')).hexdigest()

                    extracted_cves = extract_cves(f"{title} {summary} {content}")
                    cve_dicts = [{"id": cve, "source": feed_name} for cve in extracted_cves]

                    intel_item = IntelligenceItem(
                        id=item_id,
                        title=title,
                        summary=summary[:500],
                        content=content[:2000],
                        published_at=pub_date,
                        source_name=feed_name,
                        source_url=link,
                        category=category_hint,
                        cves=cve_dicts
                    )
                    items.append(intel_item)
                    count += 1

                logger.info(f"Collected {count} fresh items from {feed_name}")

            except Exception as e:
                logger.error(f"Error collecting RSS feed {feed_name}: {e}")

        return items
