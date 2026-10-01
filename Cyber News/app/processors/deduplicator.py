import re
from difflib import SequenceMatcher
from typing import List, Set
from app.models import IntelligenceItem
from app.utils.logger import logger

# Priority order for authoritative sources
AUTHORITATIVE_SOURCES = ["CISA KEV Catalog", "CISA Cybersecurity Advisories", "Microsoft Security Blog", "Google Security Blog", "Palo Alto Networks Unit 42", "Cisco Talos Intelligence"]

def text_similarity(str1: str, str2: str) -> float:
    """Calculate normalized similarity between two strings."""
    s1 = re.sub(r'[^a-zA-Z0-9\s]', '', str1.lower()).strip()
    s2 = re.sub(r'[^a-zA-Z0-9\s]', '', str2.lower()).strip()
    
    # Word set Jaccard similarity
    words1 = set(s1.split())
    words2 = set(s2.split())
    if not words1 or not words2:
        return 0.0
    
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    jaccard = len(intersection) / len(union)

    # Sequence matcher ratio for exact phrasing
    seq_ratio = SequenceMatcher(None, s1, s2).ratio()
    return max(jaccard, seq_ratio)

class Deduplicator:
    """Deduplicates news stories based on CVE IDs and Title similarity."""

    def __init__(self, similarity_threshold: float = 0.60):
        self.similarity_threshold = similarity_threshold

    def is_authoritative(self, source_name: str) -> bool:
        return any(auth.lower() in source_name.lower() for auth in AUTHORITATIVE_SOURCES)

    def deduplicate(self, items: List[IntelligenceItem]) -> List[IntelligenceItem]:
        if not items:
            return []

        logger.info(f"Starting deduplication on {len(items)} collected items...")
        unique_items: List[IntelligenceItem] = []

        for item in items:
            merged = False
            item_cves = set(c["id"] for c in item.cves if "id" in c)

            for existing in unique_items:
                existing_cves = set(c["id"] for c in existing.cves if "id" in c)

                # Check 1: CVE overlap match
                cve_match = bool(item_cves and existing_cves and item_cves.intersection(existing_cves))

                # Check 2: Title similarity match
                sim = text_similarity(item.title, existing.title)
                title_match = sim >= self.similarity_threshold

                if cve_match or title_match:
                    merged = True
                    logger.debug(f"Duplicate found: '{item.title}' matches '{existing.title}' (sim: {sim:.2f}, CVE match: {cve_match})")

                    # Decide which item stays as primary
                    if self.is_authoritative(item.source_name) and not self.is_authoritative(existing.source_name):
                        # Swap primary with authoritative item
                        secondary_source = {"name": existing.source_name, "url": existing.source_url}
                        existing.corroborating_sources.append(secondary_source)
                        existing.corroborating_sources.extend(item.corroborating_sources)
                        
                        # Update primary fields
                        existing.title = item.title
                        existing.source_name = item.source_name
                        existing.source_url = item.source_url
                        existing.summary = item.summary or existing.summary
                    else:
                        existing.corroborating_sources.append({"name": item.source_name, "url": item.source_url})
                        existing.corroborating_sources.extend(item.corroborating_sources)

                    # Merge CVEs
                    all_cve_ids = set(c["id"] for c in existing.cves)
                    for cve_obj in item.cves:
                        if cve_obj["id"] not in all_cve_ids:
                            existing.cves.append(cve_obj)
                            all_cve_ids.add(cve_obj["id"])

                    break

            if not merged:
                unique_items.append(item)

        logger.info(f"Deduplication complete. Reduced {len(items)} items -> {len(unique_items)} unique intelligence items.")
        return unique_items
