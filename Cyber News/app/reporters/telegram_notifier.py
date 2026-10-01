import requests
from pathlib import Path
from typing import Dict, Any
from app.utils.logger import logger
from config import config

class TelegramNotifier:
    """Delivers daily cybersecurity intelligence reports via Telegram Bot API."""

    def __init__(self, bot_token: str = None, chat_id: str = None):
        self.bot_token = bot_token or config.TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or config.TELEGRAM_CHAT_ID

    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send_report(self, report_md: str, report_filepath: Path, analysis_data: Dict[str, Any]) -> bool:
        if not self.is_configured():
            logger.info("Telegram credentials not provided. Skipping Telegram delivery.")
            return False

        logger.info(f"Sending daily intelligence report to Telegram chat {self.chat_id}...")

        # 1. Prepare concise text summary for Telegram message body
        exec_summary = analysis_data.get("executive_summary", [])
        top_10 = analysis_data.get("top_10", [])

        summary_bullets = "\n".join([f"• {b}" for b in exec_summary[:5]])
        top_items_str = "\n".join([f"{idx+1}. [{item.priority}] {item.title[:60]}" for idx, item in enumerate(top_10[:5])])

        msg_body = f"""🛡️ *CYBERSECURITY DAILY INTELLIGENCE REPORT*

📅 *Date:* {report_filepath.stem}

⚡ *Executive Summary:*
{summary_bullets or "• No major critical incidents reported today."}

📌 *Top Critical Items:*
{top_items_str or "• See attached report."}

📎 *Full Markdown report attached below.*
"""

        # Truncate text if needed to stay well under 4096 char limit
        if len(msg_body) > 3800:
            msg_body = msg_body[:3800] + "\n...\n(Full report attached)"

        text_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        text_payload = {
            "chat_id": self.chat_id,
            "text": msg_body,
            "parse_mode": "Markdown"
        }

        try:
            # Send text summary
            resp_text = requests.post(text_url, json=text_payload, timeout=15)
            if resp_text.status_code != 200:
                # Try sending without parse_mode if markdown formatting failed
                text_payload.pop("parse_mode")
                requests.post(text_url, json=text_payload, timeout=15)

            # Send document file attachment (.md report)
            doc_url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
            if report_filepath.exists():
                with open(report_filepath, "rb") as doc_file:
                    files = {"document": (report_filepath.name, doc_file, "text/markdown")}
                    data = {"chat_id": self.chat_id, "caption": f"📄 Full Report: {report_filepath.name}"}
                    resp_doc = requests.post(doc_url, data=data, files=files, timeout=20)
                    if resp_doc.status_code == 200:
                        logger.info("Successfully sent full Markdown report document to Telegram.")
                    else:
                        logger.warning(f"Failed to send Telegram document: {resp_doc.text}")

            logger.info("Telegram notification completed successfully.")
            return True

        except Exception as e:
            logger.error(f"Error delivering Telegram notification: {e}")
            return False
