"""
Code Utilities - Common code processing functions
"""

import re
import difflib
import os


def normalize_language(language: str) -> str:
    """
    Normalize language string to 'C' or 'C++'

    Handles: c, C, cpp, CPP, Cpp, c++, C++, cxx, CXX, cc, CC, etc.

    Args:
        language: Language string (case-insensitive)

    Returns:
        Normalized language string: 'C' or 'C++'

    Examples:
        >>> normalize_language('c')
        'C'
        >>> normalize_language('C++')
        'C++'
        >>> normalize_language('cpp')
        'C++'
        >>> normalize_language('cxx')
        'C++'
        >>> normalize_language('unknown')
        'C'
    """
    lang_upper = language.upper().strip()

    # C++ variants
    if lang_upper in ['C++', 'CPP', 'CXX', 'CC']:
        return 'C++'

    # C (default for unknown)
    return 'C'


def generate_git_diff(old_code: str, new_code: str, file_path: str, context_lines: int = 3) -> str:
    """
    Generate git diff format string from old and new code

    Args:
        old_code: Original code
        new_code: Modified code
        file_path: File path for diff header
        context_lines: Number of context lines to include (default: 3)

    Returns:
        Git diff format string (unified diff)
    """
    # Normalize file path for diff header (use basename)
    diff_path = os.path.basename(file_path)

    # Split code into lines (keep line endings for proper diff)
    old_lines = old_code.splitlines(True) if old_code else []
    new_lines = new_code.splitlines(True) if new_code else []

    # If no line endings, add them
    if old_lines and not old_lines[-1].endswith('\n'):
        old_lines[-1] += '\n'
    if new_lines and not new_lines[-1].endswith('\n'):
        new_lines[-1] += '\n'

    # Generate unified diff (lineterm='' means lines don't end with newline)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{diff_path}",
        tofile=f"b/{diff_path}",
        n=context_lines,
        lineterm=''
    )

    # Join diff lines and ensure each line has newline
    diff_lines = list(diff)
    if not diff_lines:
        return ""

    # Add newline to each line if missing
    diff_str = ''.join(line if line.endswith('\n') else line + '\n' for line in diff_lines)

    return diff_str


_FENCE_OPEN_RE = re.compile(r'^\s*```\s*(c|cpp|c\+\+|cxx|cc|C|CC|C\+\+|CXX)?\s*$')
_FENCE_CLOSE_RE = re.compile(r'^\s*```\s*$')
_ENTRYPOINT_BODY_RE = re.compile(r'\bLLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{', re.DOTALL)


def _scan_fenced_blocks(text: str) -> list:
    """Line-based scanner for fenced code blocks.

    Tolerates the common LLM failure mode of an unclosed opening fence followed
    by another opening fence (treats the first block as malformed and restarts
    from the second). Only bare ``` lines count as closing fences; opening
    fences may carry a language tag.

    Returns a list of {'text': str, 'lang': str, 'complete': bool}.
    """
    blocks = []
    in_block = False
    current_lines = []
    current_lang = ''
    for line in text.split('\n'):
        if in_block:
            # Bare ``` closes the current block. A language-tagged ```cpp/```c
            # while already open is treated as a restart (previous block malformed).
            if _FENCE_CLOSE_RE.match(line):
                blocks.append({
                    'text': '\n'.join(current_lines).strip(),
                    'lang': current_lang,
                    'complete': True,
                })
                in_block = False
                current_lines = []
                current_lang = ''
                continue
            new_open = _FENCE_OPEN_RE.match(line)
            if new_open and new_open.group(1):
                # Unclosed previous block + new language-tagged opening: discard
                # the malformed previous block and start fresh.
                in_block = True
                current_lines = []
                current_lang = new_open.group(1).lower()
                continue
            current_lines.append(line)
        else:
            open_match = _FENCE_OPEN_RE.match(line)
            if open_match:
                in_block = True
                current_lang = (open_match.group(1) or '').lower()
                current_lines = []
    if in_block and current_lines:
        # File ended without closing fence; keep as incomplete candidate.
        blocks.append({
            'text': '\n'.join(current_lines).strip(),
            'lang': current_lang,
            'complete': False,
        })
    return blocks


def _pick_best_block(blocks: list) -> str:
    """Score and pick the most likely driver code from candidate blocks.

    Priority:
      1. Last block containing a full LLVMFuzzerTestOneInput function signature+body.
      2. Last block containing the LLVMFuzzerTestOneInput identifier.
      3. Last block containing any code-like indicator + size > 100.
      4. Largest block.
    """
    if not blocks:
        return ''

    entry_body = [b for b in blocks if _ENTRYPOINT_BODY_RE.search(b['text'])]
    if entry_body:
        return entry_body[-1]['text']

    entry_name = [b for b in blocks if 'LLVMFuzzerTestOneInput' in b['text']]
    if entry_name:
        return entry_name[-1]['text']

    indicators = ('int main(', 'extern "C"', '#include')
    indicated = [b for b in blocks
                 if any(ind in b['text'] for ind in indicators)
                 and len(b['text']) > 100]
    if indicated:
        return indicated[-1]['text']

    largest = max(blocks, key=lambda b: len(b['text']))
    if len(largest['text']) > 100:
        return largest['text']

    return blocks[-1]['text']


def extract_code_from_markdown(text: str, fallback_patterns: list = None) -> str:
    """
    Extract code from markdown code blocks or LLM response.

    Strategy order:
    1. Line-based scanner that tolerates malformed/unclosed fences and back-to-back
       language openings, then scoring candidates by entrypoint presence.
    2. Legacy non-greedy regex (kept for backward compat on simple inputs).
    3. Tail-anchored recovery: from the last bare ``` walk backwards to the
       nearest language opening and return the enclosed text.
    4. Caller-supplied fallback regex patterns.
    5. Raw text.

    Args:
        text: Text that may contain code blocks
        fallback_patterns: Optional list of regex patterns for fallback extraction

    Returns:
        Extracted code string

    Examples:
        >>> extract_code_from_markdown('```cpp\\nint main() { return 0; }\\n```')
        'int main() { return 0; }'
    """
    if not text:
        return ""

    # Strategy 1: line-based scanner with malformed-fence tolerance.
    blocks = _scan_fenced_blocks(text)
    if blocks:
        best = _pick_best_block(blocks)
        if best:
            return best

    # Strategy 2: legacy non-greedy regex (handles inline-only inputs).
    code_block_pattern = r'```(?:c|C|cpp|c\+\+|C\+\+|cxx|CXX|cc|CC)?\s*\n(.*?)\n```'
    matches = re.findall(code_block_pattern, text, re.DOTALL)
    if matches:
        for code_block in reversed(matches):
            code_text = code_block.strip()
            if 'LLVMFuzzerTestOneInput' in code_text and len(code_text) > 100:
                return code_text
        largest_block = max(matches, key=len).strip()
        if len(largest_block) > 100:
            return largest_block
        return matches[-1].strip()

    # Strategy 3: tail-anchored recovery from the last bare ``` upward.
    lines = text.split('\n')
    last_close = -1
    for i in range(len(lines) - 1, -1, -1):
        if _FENCE_CLOSE_RE.match(lines[i]):
            last_close = i
            break
    if last_close > 0:
        for j in range(last_close - 1, -1, -1):
            open_match = _FENCE_OPEN_RE.match(lines[j])
            if open_match and open_match.group(1):
                candidate = '\n'.join(lines[j + 1:last_close]).strip()
                if candidate:
                    return candidate
                break

    # Strategy 4: caller-supplied fallback patterns.
    if fallback_patterns:
        for pattern in fallback_patterns:
            match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
            if match:
                return match.group(1).strip() if match.groups() else match.group(0).strip()

    # Strategy 5: return full content.
    return text.strip()
