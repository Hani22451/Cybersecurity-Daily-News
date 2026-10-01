# Cybersecurity Daily Intelligence Agent

An automated, zero-cost, Python-based threat intelligence agent that collects cybersecurity information from authoritative sources (CISA KEV, CISA Advisories, BleepingComputer, Krebs on Security, Dark Reading, Microsoft, Google, Cloudflare, Palo Alto Unit 42, Cisco Talos, etc.), deduplicates identical stories, categorizes security events, assesses defensive risk, generates structured Markdown reports, and delivers daily alerts via Telegram.

---

## 📁 Project Folder Structure

```
cybersecurity-news-automation/
│
├── .github/
│   └── workflows/
│       └── daily_report.yml    # GitHub Actions workflow for daily automated runs
│
├── app/
│   ├── __init__.py
│   ├── models.py               # IntelligenceItem data models
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base_collector.py   # Abstract base collector
│   │   ├── rss_collector.py    # RSS & Atom feed parser
│   │   └── cisa_kev_collector.py # CISA Known Exploited Vulnerabilities parser
│   ├── processors/
│   │   ├── __init__.py
│   │   ├── deduplicator.py     # Story similarity & CVE-based deduplication
│   │   └── categorizer.py      # Category & defensive risk priority classifier
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── base_analyzer.py    # Analyzer interface
│   │   ├── gemini_analyzer.py  # Google Gemini AI analyzer
│   │   ├── openai_analyzer.py  # OpenAI GPT-4o-mini analyzer
│   │   ├── fallback_analyzer.py # 100% offline zero-cost rule-based analyzer
│   │   └── analyzer_factory.py # Dynamic analyzer selector
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── markdown_reporter.py # Markdown daily report generator
│   │   └── telegram_notifier.py # Telegram bot notifier & report attachment sender
│   └── utils/
│       ├── __init__.py
│       ├── logger.py           # Logging utility (console & agent.log)
│       └── helpers.py          # Datetime, HTML cleaning, and CVE parser helpers
│
├── config/
│   ├── config.py               # Environment & system settings
│   └── sources.json            # RSS feed URLs & CISA configuration
│
├── reports/                    # Directory where daily reports (.md) are saved
│   └── .gitkeep
│
├── tests/
│   ├── __init__.py
│   └── test_agent.py           # Unit test suite
│
├── .env.example                # Template environment variables
├── .gitignore
├── requirements.txt            # Python dependencies
├── main.py                     # Agent CLI entrypoint
└── README.md                   # Documentation
```

---

## 🚀 Beginner-Friendly Step-by-Step Setup Guide

### STEP 1 — Install Python
Ensure Python 3.10 or higher is installed on your computer.
- **Windows / Mac / Linux:** Download from [python.org](https://www.python.org/downloads/).
- Verify installation in your terminal / command prompt:
  ```bash
  python --version
  ```

---

### STEP 2 — Download / Clone the Project
Open terminal or command prompt and clone the repository:
```bash
git clone https://github.com/Hani22451/cybersecurity-news-automation.git
cd cybersecurity-news-automation
```

---

### STEP 3 — Install Dependencies
Install all required Python packages:
```bash
pip install -r requirements.txt
```

---

### STEP 4 — Configure Environment Variables
Copy `.env.example` to create your local `.env` file:
- **On Windows (Command Prompt):**
  ```cmd
  copy .env.example .env
  ```
- **On Linux / Mac / PowerShell:**
  ```bash
  cp .env.example .env
  ```

Open `.env` in any text editor:
```env
# AI Provider (Options: fallback, gemini, openai)
# Set to fallback for 100% free offline execution without any API keys!
AI_PROVIDER=fallback
GEMINI_API_KEY=
OPENAI_API_KEY=

# Telegram Bot Credentials (Optional - leave blank if not using Telegram)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Intelligence Agent Settings
HOURS_LOOKBACK=24
MIN_ITEMS_THRESHOLD=5
OUTPUT_DIR=reports
LOG_LEVEL=INFO
```

---

### STEP 5 — Test the Agent Locally
Run the agent in **Test Mode** (fetches a small sample batch and outputs `reports/test_report.md`):
```bash
python main.py --test
```
You should see console logs showing feed collection, deduplication, categorization, analysis, and report creation.

---

### STEP 6 — Verify the Generated Report
Check the `reports/` directory. You will find `test_report.md` (or `YYYY-MM-DD.md` for regular runs). Open it to review your daily threat intelligence report!

---

### STEP 7 — Create GitHub Repository
1. Go to [GitHub.com](https://github.com) and click **New Repository**.
2. Name it `cybersecurity-news-automation` (or any name you prefer).
3. Keep it Public or Private. Do **NOT** initialize with a README (since we already have one).

---

### STEP 8 — Upload the Project to GitHub
In your local command prompt inside the project folder:
```bash
git init
git add .
git commit -m "Initial commit of Cybersecurity Daily Intelligence Agent"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cybersecurity-news-automation.git
git push -u origin main
```

---

### STEP 9 — Add GitHub Secrets (For Automated Daily Delivery & Telegram)
1. In your GitHub repository, go to **Settings** > **Secrets and variables** > **Actions**.
2. Click **New repository secret** and add the following optional secrets:
   - `AI_PROVIDER` (e.g. `fallback`, `gemini`, or `openai`)
   - `GEMINI_API_KEY` (Your Google Gemini API Key if using Gemini)
   - `OPENAI_API_KEY` (Your OpenAI API Key if using OpenAI)
   - `TELEGRAM_BOT_TOKEN` (Your Telegram Bot token)
   - `TELEGRAM_CHAT_ID` (Your Telegram Chat ID)

---

### STEP 10 — Enable GitHub Actions
1. Go to the **Actions** tab in your GitHub repository.
2. If prompted, click **I understand my workflows, go ahead and enable them**.

---

### STEP 11 — Manually Trigger the Workflow Once
1. Under **Actions**, click on **Cybersecurity Daily Intelligence Report** on the left menu.
2. Click **Run workflow** > **Run workflow**.
3. Watch the action complete. It will run `main.py`, generate the report, commit the updated markdown report to the repo, and send a message + report document to your Telegram chat.

---

### STEP 12 — Verify Telegram Report
If you configured Telegram secrets:
- Open your Telegram app.
- Check your bot chat. You will receive an Executive Summary text message followed by the complete `.md` report document attached.

---

### STEP 13 — Enable Daily Schedule
The workflow is already pre-configured to run automatically every single day at **06:00 UTC**!
No further setup is required—your PC does **not** need to stay turned on.

---

## 📲 How to Create a Telegram Bot & Find Chat ID

### Creating a Telegram Bot:
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot`.
3. Give your bot a name (e.g., `MyCyberNewsBot`) and username (e.g., `MyCyberNews_bot`).
4. `@BotFather` will give you an **HTTP API Token** (e.g., `7123456789:AAFxxxxx...`). Save this as `TELEGRAM_BOT_TOKEN`.

### Finding your Telegram Chat ID:
1. Search for `@userinfobot` on Telegram.
2. Send `/start`.
3. It will reply with your `Id` (e.g., `123456789`). Save this as `TELEGRAM_CHAT_ID`.
4. Open your new bot chat and click `/start` so it has permission to message you.

---

## ⏰ How to Change the Daily Reporting Time

The schedule is controlled by GitHub Actions cron syntax in `.github/workflows/daily_report.yml`:
```yaml
on:
  schedule:
    - cron: '0 6 * * *'  # 06:00 UTC daily
```
To change the time:
- `0 6 * * *` = 06:00 UTC (11:30 AM IST / 2:00 AM EST)
- `0 12 * * *` = 12:00 UTC (5:30 PM IST / 8:00 AM EST)
- Edit the cron expression in `.github/workflows/daily_report.yml` and push the changes.

---

## 📰 How to Add or Remove News Sources

All news sources are stored in `config/sources.json`.

To add a new RSS feed:
1. Open `config/sources.json`.
2. Add a new feed object under `"rss_feeds"`:
   ```json
   {
     "name": "New Security Blog",
     "url": "https://example.com/rss.xml",
     "category_hint": "SECURITY RESEARCH",
     "enabled": true
   }
   ```
To disable a feed without deleting it, set `"enabled": false`.

---

## 🏷️ How to Change Report Categories & Risk Rules

Categories and risk priority logic are defined in `app/processors/categorizer.py`.

- Add or update regular expressions in `CATEGORY_RULES` dictionary.
- Priority assignment rules are handled in `categorize_item()`.

---

## 🛠️ Common Error Troubleshooting

| Problem | Cause | Solution |
| --- | --- | --- |
| `NameResolutionError` / `ConnectionError` | Individual feed server is down or unreachable | Agent automatically logs error and continues with remaining sources. |
| Telegram notification failed | Invalid `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` | Check credentials in `.env` or GitHub Secrets. Ensure you pressed `/start` in your bot chat. |
| AI API fails or rate limited | Missing or invalid API key | Agent automatically falls back to offline zero-cost rule-based analyzer without crashing. |
| `git push` fails in GitHub Actions | Permission missing | Go to Repo Settings > Actions > General > Workflow permissions > Select **Read and write permissions**. |

---

## 📄 License
This project is open-source and intended for defensive cybersecurity threat intelligence and educational purposes.
