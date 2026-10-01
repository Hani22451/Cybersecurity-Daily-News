import sys
import argparse
from pathlib import Path
from datetime import datetime, timezone

from config import config
from app.utils.logger import logger
from app.collectors import RSSCollector, CISAKEVCollector
from app.processors import Deduplicator, Categorizer
from app.analyzers import get_analyzer
from app.reporters import MarkdownReporter, TelegramNotifier


def run_agent(is_test_mode: bool = False, force_lookback: int = None, force_telegram: bool = False):
    logger.info("==================================================")
    logger.info("Starting Cybersecurity Daily Intelligence Agent")
    if is_test_mode:
        logger.info(">>> TEST MODE ENABLED <<<")
    logger.info("==================================================")

    # Determine lookback hours
    lookback = force_lookback or (72 if is_test_mode else config.HOURS_LOOKBACK)
    max_per_source = 3 if is_test_mode else 30

    sources_cfg = config.load_sources_config()

    # Step 1: Collection
    all_collected_items = []
    
    # Collect from CISA KEV
    cisa_cfg = sources_cfg.get("cisa_kev", {})
    if cisa_cfg.get("enabled", True):
        cisa_collector = CISAKEVCollector(url=cisa_cfg.get("url", ""))
        kev_items = cisa_collector.fetch_items(hours_lookback=lookback, max_items=max_per_source)
        all_collected_items.extend(kev_items)

    # Collect from RSS Feeds
    rss_feeds = sources_cfg.get("rss_feeds", [])
    rss_collector = RSSCollector(feeds=rss_feeds)
    rss_items = rss_collector.fetch_items(hours_lookback=lookback, max_items=max_per_source)
    all_collected_items.extend(rss_items)

    logger.info(f"Total raw items collected across all sources: {len(all_collected_items)}")

    # Offline / Test fallback mock data if no items were fetched (e.g. offline environment)
    if not all_collected_items and is_test_mode:
        logger.info("Offline/Test environment detected. Injecting sample threat intelligence items for demonstration...")
        all_collected_items = [
            IntelligenceItem(
                id="mock_1",
                title="CISA KEV ALERT: CVE-2026-9999 Critical Zero-Day Vulnerability in Web Server",
                summary="A zero-day vulnerability in popular web server software allows remote code execution without authentication.",
                content="CISA added CVE-2026-9999 to the KEV catalog. Active exploitation detected across multiple enterprise networks.",
                published_at=datetime.now(timezone.utc),
                source_name="CISA KEV Catalog",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                category="EXPLOITED VULNERABILITY",
                priority="CRITICAL",
                cves=[{"id": "CVE-2026-9999", "product": "Web Server Enterprise", "severity": "CRITICAL", "cvss": "9.8", "exploited": True, "kev": True, "patch_available": True}]
            ),
            IntelligenceItem(
                id="mock_2",
                title="LockBit Ransomware Group Targets Global Financial Institutions",
                summary="Security researchers identify new ransomware variant exploiting unpatched VPN endpoints.",
                content="New threat campaign observed targeting financial sector organizations worldwide.",
                published_at=datetime.now(timezone.utc),
                source_name="BleepingComputer",
                source_url="https://www.bleepingcomputer.com/news/security/sample-ransomware",
                category="RANSOMWARE",
                priority="HIGH"
            ),
            IntelligenceItem(
                id="mock_3",
                title="Major Cloud Storage Provider Discloses Unauthorized Data Access",
                summary="Unsecured database endpoint exposed millions of customer profile records.",
                content="An internal misconfiguration exposed corporate user emails and hashed authentication tokens.",
                published_at=datetime.now(timezone.utc),
                source_name="The Record by Recorded Future",
                source_url="https://therecord.media/sample-breach",
                category="DATA BREACH",
                priority="HIGH"
            )
        ]

    # Freshness fallback check (Requirement 3: expand lookback if not enough items)
    if len(all_collected_items) < config.MIN_ITEMS_THRESHOLD and lookback < 72:
        logger.info(f"Fewer than {config.MIN_ITEMS_THRESHOLD} items found. Expanding lookback to 72 hours...")
        rss_items_expanded = rss_collector.fetch_items(hours_lookback=72, max_items=max_per_source)
        all_collected_items.extend(rss_items_expanded)

    if not all_collected_items:
        logger.warning("No fresh cybersecurity news items collected in the lookback period.")

    # Step 2: Deduplication
    deduplicator = Deduplicator(similarity_threshold=0.55)
    unique_items = deduplicator.deduplicate(all_collected_items)

    # Step 3: Categorization & Priority Scoring
    categorizer = Categorizer()
    classified_items = categorizer.process_all(unique_items)

    # Step 4: AI / Offline Intelligence Analysis
    analyzer = get_analyzer()
    analysis_data = analyzer.analyze(classified_items)

    # Step 5: Markdown Report Generation
    reporter = MarkdownReporter(output_dir=config.OUTPUT_DIR)
    target_filename = "test_report.md" if is_test_mode else None
    report_md, report_path = reporter.generate_report(analysis_data, target_filename=target_filename)

    # Step 6: Telegram Delivery
    if (not is_test_mode or force_telegram):
        notifier = TelegramNotifier()
        notifier.send_report(report_md=report_md, report_filepath=report_path, analysis_data=analysis_data)
    else:
        logger.info("Skipping Telegram delivery in test mode (use --send-telegram to force delivery).")

    # Final Execution Summary Stats
    critical_count = sum(1 for i in classified_items if i.priority in ["CRITICAL", "HIGH"])
    logger.info("--------------------------------------------------")
    logger.info("EXECUTION SUMMARY:")
    logger.info(f"  - Total items collected: {len(all_collected_items)}")
    logger.info(f"  - Duplicates removed:   {len(all_collected_items) - len(unique_items)}")
    logger.info(f"  - Unique items analyzed: {len(unique_items)}")
    logger.info(f"  - Critical/High items:   {critical_count}")
    logger.info(f"  - Report saved to:      {report_path}")
    logger.info("==================================================")
    print(f"\n[+] Agent run complete! Report generated at: {report_path.resolve()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cybersecurity Daily Intelligence Agent")
    parser.add_argument("--test", action="store_true", help="Run in test mode (fetches fewer items, saves test_report.md)")
    parser.add_argument("--lookback", type=int, help="Override default lookback window in hours")
    parser.add_argument("--send-telegram", action="store_true", help="Force send report to Telegram even in test mode")

    args = parser.parse_args()
    run_agent(is_test_mode=args.test, force_lookback=args.lookback, force_telegram=args.send_telegram)
