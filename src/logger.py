import logging
import sys


def setup_logger(name: str = "waf"):
    """
    Creates and configures a centralized logger for the WAF system.
    """

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Prevent duplicate logs if logger is reused
    if logger.handlers:
        return logger

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(levelname)s] %(asctime)s | source=%(source)s "
        "endpoint=%(endpoint)s score=%(score)s decision=%(decision)s "
        "reasons=%(reasons)s"
    )

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
