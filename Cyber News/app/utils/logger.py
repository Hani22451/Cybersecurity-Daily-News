import logging
import sys
from pathlib import Path

def setup_logger(name: str = "CyberNewsAgent", log_level: str = "INFO") -> logging.Logger:
    """Configures a clean logger that outputs to stdout and agent.log."""
    logger = logging.getLogger(name)
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if not logger.handlers:
        # Console Handler
        c_handler = logging.StreamHandler(sys.stdout)
        c_handler.setLevel(numeric_level)
        c_format = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s', '%Y-%m-%d %H:%M:%S')
        c_handler.setFormatter(c_format)
        logger.addHandler(c_handler)

        # File Handler
        try:
            log_file = Path("agent.log")
            f_handler = logging.FileHandler(log_file, encoding='utf-8')
            f_handler.setLevel(numeric_level)
            f_format = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s', '%Y-%m-%d %H:%M:%S')
            f_handler.setFormatter(f_format)
            logger.addHandler(f_handler)
        except Exception:
            pass

    return logger

logger = setup_logger()
