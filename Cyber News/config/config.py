import os
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
SOURCES_FILE = CONFIG_DIR / "sources.json"

# Core Settings
HOURS_LOOKBACK = int(os.getenv("HOURS_LOOKBACK", "24"))
MIN_ITEMS_THRESHOLD = int(os.getenv("MIN_ITEMS_THRESHOLD", "5"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", str(BASE_DIR / "reports")))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# AI Settings
AI_PROVIDER = os.getenv("AI_PROVIDER", "fallback").lower()  # gemini, openai, fallback
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Telegram Settings
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")


def load_sources_config():
    """Load sources list from sources.json."""
    if not SOURCES_FILE.exists():
        return {"cisa_kev": {"enabled": True, "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}, "rss_feeds": []}
    
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading sources.json: {e}")
        return {"cisa_kev": {"enabled": True, "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}, "rss_feeds": []}
