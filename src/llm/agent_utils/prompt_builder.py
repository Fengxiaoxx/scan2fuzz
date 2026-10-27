"""
Prompt Builder - Utilities for building agent prompts
"""

from typing import List, Dict, Optional
from loguru import logger

from src.core.code_utils import generate_git_diff


def build_failed_attempts_section(failed_attempts: List[Dict], language: str,
                                  error_label: str = "Compilation Error",
                                  original_driver_code: Optional[str] = None,
                                  driver_file_path: Optional[str] = None) -> str:
    """Render previous failed patches as git diffs."""
    if not failed_attempts:
        return ""
    if original_driver_code is None:
        raise ValueError("original_driver_code is required for failed patch diffs")
    if not driver_file_path:
        driver_file_path = "driver.c" if language.lower() == "c" else "driver.cc"

    section = (
        "\nHere are some wrong patches you generated previously, "
        "you CAN NOT use them again:\n\n"
    )
    for attempt in failed_attempts:
        attempt_num = attempt.get(
            "attempt",
            len(
                [
                    item
                    for item in failed_attempts
                    if item.get("attempt", 0) <= attempt.get("attempt", 0)
                ]
            ),
        )
        section += f"Error case {attempt_num}:\n"
        fixed_code = attempt.get("fixed_code")
        if fixed_code:
            try:
                diff = generate_git_diff(
                    original_driver_code,
                    fixed_code,
                    driver_file_path,
                )
                section += diff or "(no differences detected)\n"
            except Exception as exc:
                logger.debug(f"Failed to generate git diff: {exc}")
                section += f"Failed patch (diff generation error: {exc})\n"
        else:
            section += "(no code generated)\n"

        compile_error = attempt.get("compile_error", "")
        if compile_error:
            section += f"\n{error_label}:\n```\n{compile_error}\n```\n"
        else:
            section += f"\n{error_label}: (no error message)\n"
        section += "\n"
    return section
