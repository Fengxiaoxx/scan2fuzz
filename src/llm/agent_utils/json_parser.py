"""
JSON Parser - Parse and clean JSON from LLM responses

Uses LangChain's JsonOutputParser as the primary extractor — it handles
JSON embedded in arbitrary noise, markdown fences, and most LLM output
patterns out of the box.  Falls back to json5 for non-standard syntax
(single quotes, trailing commas, comments).
"""

import json
import re
from typing import Dict, Optional

import json5
from langchain_core.output_parsers import JsonOutputParser

_langchain_parser = JsonOutputParser()


def _extract_complete_json(text: str, expected_type):
    """Prefer complete JSON, including fenced JSON5 surrounded by prose."""
    fences = re.findall(
        r"^[ \t]*(`{3,}|~{3,})(?:json5?|javascript)?[ \t]*\r?\n(.*?)"
        r"^[ \t]*\1[ \t]*$",
        text, re.MULTILINE | re.DOTALL | re.IGNORECASE,
    )
    candidates = [body.strip() for _, body in fences] + [text.strip()]
    for candidate in candidates:
        for loads in (json.loads, json5.loads):
            try:
                value = loads(candidate)
                if isinstance(value, expected_type):
                    return value
            except ValueError:
                pass

    decoder = json.JSONDecoder()
    opening = "{" if expected_type is dict else "["
    for candidate in candidates:
        for index, char in enumerate(candidate):
            if char != opening:
                continue
            try:
                value, _ = decoder.raw_decode(candidate, index)
                if isinstance(value, expected_type):
                    return value
            except ValueError:
                pass
    return None


def extract_json_object(text: str) -> Optional[Dict]:
    """
    Extract the first valid JSON object from arbitrary LLM output.

    Strategy:
      1. LangChain JsonOutputParser  — handles markdown fences, simple noise.
      2. raw_decode scan             — scans every '{' position in the text and
                                       tries to parse from there; correctly skips
                                       '{' characters inside C/code blocks.
      3. json5 fallback              — handles single quotes, trailing commas,
                                       JS comments.
    """
    if not text:
        return None

    result = _extract_complete_json(text, dict)
    if result is not None:
        return result

    # Strategy 1: LangChain parser
    try:
        result = _langchain_parser.parse(text)
        if isinstance(result, dict):
            return result
    except Exception:
        pass

    # Strategy 2: scan every '{' with raw_decode — correctly handles responses
    # where code blocks (e.g. C source) contain '{' before the actual JSON.
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == '{':
            try:
                obj, _ = decoder.raw_decode(text, i)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue

    # Strategy 3: json5 on full text (single quotes, trailing commas, comments)
    try:
        result = json5.loads(text.strip())
        if isinstance(result, dict):
            return result
    except Exception:
        pass

    return None
