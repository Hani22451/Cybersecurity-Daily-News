import json
from typing import List, Dict, Any
from app.analyzers.base_analyzer import BaseAnalyzer
from app.analyzers.fallback_analyzer import FallbackAnalyzer
from app.models import IntelligenceItem
from app.utils.logger import logger

class OpenAIAnalyzer(BaseAnalyzer):
    """AI Analyzer powered by OpenAI API."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.fallback = FallbackAnalyzer()

    def analyze(self, items: List[IntelligenceItem]) -> Dict[str, Any]:
        if not self.api_key:
            logger.warning("OpenAI API key missing. Falling back to offline analyzer.")
            return self.fallback.analyze(items)

        logger.info(f"Analyzing {len(items)} items using OpenAI API...")

        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)

            prepared_data = []
            for item in items:
                prepared_data.append({
                    "id": item.id,
                    "title": item.title,
                    "summary": item.summary,
                    "source": item.source_name,
                    "category": item.category,
                    "cves": [c["id"] for c in item.cves]
                })

            prompt = f"""
You are a lead Cybersecurity Threat Intelligence Analyst.
Analyze the following collected cybersecurity news items and provide structured JSON analysis.

CRITICAL REQUIREMENT: Do NOT invent missing information. Every claim must be strictly derived from the provided source items.

Input Items:
{json.dumps(prepared_data, indent=2)}

Return ONLY a valid JSON object matching this structure:
{{
  "executive_summary": [
    "Bullet 1 summary of major threat/vulnerability",
    "Bullet 2..."
  ],
  "item_enhancements": {{
    "item_id_here": {{
      "risk_explanation": "Brief defensive explanation of why this matters",
      "defensive_actions": ["Action 1", "Action 2"],
      "priority": "CRITICAL|HIGH|MEDIUM|LOW|INFO"
    }}
  }},
  "defender_actions": {{
    "immediate": ["Immediate Action 1", "Immediate Action 2"],
    "this_week": ["Action for this week 1"],
    "monitor": ["Item to monitor 1"]
  }}
}}
"""

            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity intelligence analyst."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )

            result_json = json.loads(response.choices[0].message.content)

            enhancements = result_json.get("item_enhancements", {})
            for item in items:
                if item.id in enhancements:
                    enh = enhancements[item.id]
                    if "risk_explanation" in enh:
                        item.risk_explanation = enh["risk_explanation"]
                    if "defensive_actions" in enh and isinstance(enh["defensive_actions"], list):
                        item.defensive_actions = enh["defensive_actions"]
                    if "priority" in enh and enh["priority"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                        item.priority = enh["priority"]

            fallback_res = self.fallback.analyze(items)
            
            return {
                "executive_summary": result_json.get("executive_summary", fallback_res["executive_summary"]),
                "refined_items": items,
                "defender_actions": result_json.get("defender_actions", fallback_res["defender_actions"]),
                "top_10": fallback_res["top_10"]
            }

        except Exception as e:
            logger.error(f"OpenAI API analysis failed: {e}. Falling back to offline rule-based analyzer.")
            return self.fallback.analyze(items)
