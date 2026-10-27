"""
Agent Validators - Validation logic for agent outputs
"""

from typing import Tuple


def validate_agent_output(output: str, language: str = "C") -> Tuple[bool, str]:
    """
    Validate agent output to ensure it's valid code

    Args:
        output: Agent output string
        language: Programming language (C or C++)

    Returns:
        Tuple of (is_valid: bool, reason: str)
    """
    if not output:
        return False, "EMPTY_OUTPUT"

    # Check for invalid patterns
    invalid_patterns = [
        '[complete fixed code]',
        'Agent stopped due to iteration limit',
        'Agent stopped due to time limit',
        'Agent stopped due to',
        'iteration limit',
        'time limit'
    ]

    for pattern in invalid_patterns:
        if pattern in output:
            return False, f"INVALID_PATTERN: {pattern}"

    # Check minimum length
    if len(output) < 50:
        return False, f"TOO_SHORT: {len(output)} chars"

    # Check for C/C++ code characteristics
    code_indicators = ['#include', 'int main', 'extern "C"', 'LLVMFuzzerTestOneInput', 'void', 'return']
    if not any(indicator in output for indicator in code_indicators):
        return False, "NOT_C_CODE"

    return True, "VALID_CODE"
