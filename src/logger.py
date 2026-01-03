import logging
import sys
from pathlib import Path

from src.config import ConfigLoader


def setup_logger(name: str = "waf"):
    """
    Creates and configures a centralized logger for the WAF system
    based on external configuration.
    """

    logger = logging.getLogger(name)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Load logging configuration
    loader = ConfigLoader()
    logging_config = loader.get_logging_config()

    # Logging level
    level_name = logging_config.get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(levelname)s] %(asctime)s | "
        "source=%(source)s endpoint=%(endpoint)s "
        "score=%(score)s decision=%(decision)s "
        "reasons=%(reasons)s"
    )

    # Console handler (always enabled)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Optional file logging
    if logging_config.get("log_to_file", False):
        log_path = Path(logging_config.get("log_file_path", "logs/waf.log"))
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
