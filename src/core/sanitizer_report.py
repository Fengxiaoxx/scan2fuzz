"""Deterministic extraction of symbolized sanitizer crash reports."""

from __future__ import annotations

import re
from dataclasses import dataclass


_FRAME = re.compile(r"^\s*#\d+\s+.+")
_SOURCE_LOCATION = re.compile(
    r"(?:^|\s)(?P<location>[^\s:]+\.(?:c|cc|cpp|cxx|h|hh|hpp):\d+(?::\d+)?)"
)
_LIBFUZZER_OOM = "ERROR: libFuzzer: out-of-memory"
# Each marker opens one fault; LeakSanitizer lists one allocation stack per direct leak.
_FAULT_MARKERS = (
    "ERROR: AddressSanitizer:",
    "WARNING: MemorySanitizer:",
    "runtime error:",
    "Direct leak of",
)
_STACK_FRAME = re.compile(r"^\s*#\d+\s+0x[0-9a-fA-F]+(?:\s+in\s+(?P<body>.+))?$")
_FRAME_SOURCE = re.compile(
    r"\s(?P<file>\S+\.(?:c|cc|cpp|cxx|h|hh|hpp))"
    r"(?::\d+(?::\d+)?)?$"
)
_FUZZER_ENTRY = "LLVMFuzzerTestOneInput"

CRASH_TARGET = "target"
CRASH_DRIVER = "driver"
CRASH_OTHER = "other"


class SanitizerReportParseError(ValueError):
    """The SAN run did not produce a symbolized source frame."""


@dataclass(frozen=True)
class SanitizerReport:
    headline: str
    summary: str
    frames: tuple[str, ...]
    source_locations: tuple[str, ...]

    def format(self) -> str:
        frames = "\n".join(self.frames)
        locations = (
            "\n".join(f"- {item}" for item in self.source_locations)
            or "- (not emitted by libFuzzer for this out-of-memory failure)"
        )
        return (
            f"Headline: {self.headline}\n"
            f"Summary: {self.summary}\n"
            f"Symbolized source locations:\n{locations}\n"
            f"Stack frames:\n{frames}"
        )


def parse_sanitizer_report(output: str) -> SanitizerReport:
    """Extract stable repair fields and require one source location."""
    if not isinstance(output, str) or not output.strip():
        raise SanitizerReportParseError("sanitizer output is empty")
    lines = output.splitlines()
    headline = next(
        (
            line.strip()
            for line in lines
            if "ERROR:" in line or "runtime error:" in line
        ),
        "",
    )
    summary = next(
        (line.strip() for line in reversed(lines) if "SUMMARY:" in line),
        headline,
    )
    frames = tuple(line.rstrip() for line in lines if _FRAME.match(line))
    locations = []
    for line in lines:
        match = _SOURCE_LOCATION.search(line)
        if match and match.group("location") not in locations:
            locations.append(match.group("location"))
    if not locations and _LIBFUZZER_OOM not in headline:
        raise SanitizerReportParseError(
            "sanitizer report has no symbolized C/C++ source location"
        )
    return SanitizerReport(
        headline=headline,
        summary=summary,
        frames=frames,
        source_locations=tuple(locations),
    )


def format_sanitizer_report_for_repair(output: str) -> str:
    """Return a repair-safe report block for every abnormal process exit."""
    try:
        return parse_sanitizer_report(output).format()
    except SanitizerReportParseError as exc:
        return (
            "Unavailable: no symbolized ASan/UBSan report was emitted.\n"
            f"Parser reason: {exc}\n"
            "Treat the process exit details and driver source as the repair evidence."
        )


def _function_name(function: str) -> str:
    """Drop a trailing demangled parameter list: ``ns::f(int, char*) const`` -> ``ns::f``."""
    text = function.strip().removesuffix(" const")
    if not text.endswith(")"):
        return text
    depth = 0
    for index in range(len(text) - 1, -1, -1):
        depth += {")": 1, "(": -1}.get(text[index], 0)
        if depth == 0:
            return text[:index]
    return text


def _fault_stacks(output: str) -> list[list[tuple[str, str]]]:
    """Source frames ``(function, file)`` of every fault's first stack, innermost first."""
    stacks: list[list[tuple[str, str]]] = []
    frames: list[tuple[str, str]] | None = None
    in_stack = False
    for line in output.splitlines():
        if any(marker in line for marker in _FAULT_MARKERS):
            frames = []
            stacks.append(frames)
            in_stack = False
            continue
        if frames is None:
            continue
        frame = _STACK_FRAME.match(line)
        if frame is None:
            if in_stack:  # later stacks (allocation site, leak origin) are not the fault
                frames = None
            continue
        in_stack = True
        body = frame.group("body") or ""
        source = _FRAME_SOURCE.search(body)
        if source:
            frames.append((_function_name(body[: source.start()]), source.group("file")))
    return stacks


def attribute_sanitizer_report(output: str, *, target_function: str) -> str:
    """Say whose fault a sanitizer report shows: the target's, the driver's, or other.

    Each fault stack is read innermost first over its source frames. A stack whose
    innermost source frame is in the fuzzer entry's file is the driver's; the report
    is the target's only when every fault stack passes through the target function.
    A fault printed without source frames (UBSan omits its stack by default) says
    nothing about whose it is and is left out.
    """
    stacks = [stack for stack in _fault_stacks(output) if stack]
    driver_files = {
        file for stack in stacks for function, file in stack if function == _FUZZER_ENTRY
    }
    target = _function_name(target_function)
    verdicts = set()
    for stack in stacks:
        if stack[0][1] in driver_files:
            verdicts.add(CRASH_DRIVER)
        elif any(function == target for function, _ in stack):
            verdicts.add(CRASH_TARGET)
        else:
            verdicts.add(CRASH_OTHER)
    if CRASH_DRIVER in verdicts:
        return CRASH_DRIVER
    return CRASH_TARGET if verdicts == {CRASH_TARGET} else CRASH_OTHER
