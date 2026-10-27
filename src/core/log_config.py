"""Shared Loguru configuration that is independent of CLI entrypoints."""

from __future__ import annotations

from pathlib import Path

from loguru import logger


SIMPLE_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | <level>{message}</level>"
)

DETAILED_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)


def configure_logger(debug: bool = False, detailed: bool = False) -> None:
    """Apply the common console logging configuration."""
    logger.remove()
    logger.add(
        lambda message: print(message, end=""),
        level="DEBUG" if debug else "INFO",
        format=DETAILED_LOG_FORMAT if detailed else SIMPLE_LOG_FORMAT,
        colorize=True,
    )


def add_file_log_sink(log_path: str | Path, debug: bool = False) -> int:
    """Attach one detailed file sink and return its Loguru handler id."""
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return logger.add(
        path,
        level="DEBUG" if debug else "INFO",
        format=DETAILED_LOG_FORMAT,
        colorize=False,
        encoding="utf-8",
        enqueue=True,
    )
