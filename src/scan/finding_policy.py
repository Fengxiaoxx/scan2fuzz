"""Fixed finding-selection policy for sanitizer-focused fuzzing."""

from typing import FrozenSet


# These official CodeQL rules describe security properties that cannot be
# validated by ASan, UBSan, or the LSan runtime bundled with ASan.
SANITIZER_UNRELATED_CODEQL_RULES: FrozenSet[str] = frozenset(
    {
        "cpp/cleartext-storage-file",
        "cpp/cleartext-transmission",
        "cpp/memset-may-be-deleted",
        "cpp/path-injection",
        "cpp/potentially-dangerous-function",
        "cpp/sql-injection",
        "cpp/system-data-exposure",
        "cpp/toctou-race-condition",
        "cpp/weak-cryptographic-algorithm",
        "cpp/world-writable-file-creation",
    }
)

# These Infer issue types are performance or API-quality recommendations, not
# sanitizer-detectable runtime failures.
SANITIZER_UNRELATED_INFER_TYPES: FrozenSet[str] = frozenset(
    {
        "PULSE_CONST_REFABLE",
        "PULSE_UNNECESSARY_COPY",
        "PULSE_UNNECESSARY_COPY_ASSIGNMENT",
        "PULSE_UNNECESSARY_COPY_INTERMEDIATE",
    }
)


def keep_codeql_rule(rule_id: str) -> bool:
    """Keep every CodeQL rule except the explicit sanitizer-unrelated set."""
    return rule_id not in SANITIZER_UNRELATED_CODEQL_RULES


def keep_infer_type(bug_type: str) -> bool:
    """Keep every Infer type except the explicit sanitizer-unrelated set."""
    return bug_type not in SANITIZER_UNRELATED_INFER_TYPES
