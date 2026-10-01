from app.analyzers.base_analyzer import BaseAnalyzer
from app.analyzers.fallback_analyzer import FallbackAnalyzer
from app.analyzers.gemini_analyzer import GeminiAnalyzer
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.utils.logger import logger
from config import config

def get_analyzer(provider: str = None) -> BaseAnalyzer:
    """Factory method to select and return the appropriate analyzer."""
    selected_provider = (provider or config.AI_PROVIDER).lower()

    if selected_provider == "gemini":
        if config.GEMINI_API_KEY:
            logger.info("Initializing Gemini AI Analyzer")
            return GeminiAnalyzer(api_key=config.GEMINI_API_KEY)
        else:
            logger.warning("GEMINI_API_KEY not configured. Falling back to offline analyzer.")
            return FallbackAnalyzer()

    elif selected_provider == "openai":
        if config.OPENAI_API_KEY:
            logger.info("Initializing OpenAI Analyzer")
            return OpenAIAnalyzer(api_key=config.OPENAI_API_KEY)
        else:
            logger.warning("OPENAI_API_KEY not configured. Falling back to offline analyzer.")
            return FallbackAnalyzer()

    else:
        logger.info("Initializing Zero-Cost Offline Fallback Analyzer")
        return FallbackAnalyzer()
