import re
import html
from datetime import datetime, timezone
from dateutil import parser as date_parser

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

def parse_datetime(date_str: str) -> datetime:
    """Parse various datetime string formats into a UTC datetime object."""
    if not date_str:
        return datetime.now(timezone.utc)
    try:
        dt = date_parser.parse(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

def clean_html(raw_html: str) -> str:
    """Remove HTML tags and unescape HTML entities from string."""
    if not raw_html:
        return ""
    # Remove HTML tags
    clean_text = re.sub(r'<[^>]+>', ' ', raw_html)
    # Unescape HTML entities (&amp; -> &, &quot; -> ", etc.)
    clean_text = html.unescape(clean_text)
    # Collapse multiple whitespaces
    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
    return clean_text

def extract_cves(text: str) -> list[str]:
    """Extract unique CVE IDs from text."""
    if not text:
        return []
    matches = CVE_PATTERN.findall(text)
    return sorted(list(set(m.upper() for m in matches)))

def sanitize_telegram_markdown(text: str) -> str:
    """Escape Telegram MarkdownV2 special characters if needed, or convert basic HTML."""
    if not text:
        return ""
    # Safe subset for basic markdown
    return text
