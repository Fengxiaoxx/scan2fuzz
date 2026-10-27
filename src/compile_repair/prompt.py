"""编译失败和运行时修复分别使用的完整提示词模板。"""

COMPILE_REPAIR_PROMPT_TEMPLATE = """You are responsible for fixing compilation errors in a libFuzzer driver.

Use the current fuzz driver as the baseline. Fix only errors supported by clear evidence; do not redesign the test scenario.

## Context

Repair mode for this round: compile
Library name: {library_name}
Programming language: {language}
Library root: {library_root}
Driver file path: {driver_file}

### Current driver source code

```cpp
{driver_code}
```

### Compilation errors

```
{error_message}
```

{failed_attempts_section}

## Repair and delivery

- Locate the problem using the compiler diagnostics. If necessary, consult the public headers and relevant source code of the current library version, then make the minimal correction.
- Use only Edit to modify the specified driver file, treating the current file on disk as authoritative. Library source and build configuration are for inspection only.
- Do not compile or run it yourself; the workflow will verify the repair and return new diagnostics.
- Save the repair directly to the file. Briefly describe the changes in your response; do not repeat the complete code block.
"""


RUNTIME_REPAIR_PROMPT_TEMPLATE = """You are responsible for analyzing a libFuzzer driver's runtime failure and distinguishing driver errors from library defects.

Use the current fuzz driver as the baseline. Fix only errors supported by clear evidence; do not redesign the test scenario.

## Context

Repair mode for this round: runtime
Library name: {library_name}
Programming language: {language}
Library root: {library_root}
Driver file path: {driver_file}

### Current driver source code

```cpp
{driver_code}
```

### Failure reported by the runtime detector

```
{error_message}
```

### Crash artifacts retained for the next runtime detection

{artifact_paths}

## Attribution and repair

Determine the cause from the runtime report, the current driver, the library's public API contract, and relevant source code. Do not classify a failure as a library defect solely because it occurred inside the library.

- Driver error: after confirming that an error in the driver itself or a violation of the API contract caused this failure, use Edit to make the minimal correction in the specified file. Briefly describe the evidence and change, and end your response with VERDICT: driver_fault on its own line.
- Library defect: after confirming that the relevant calls comply with the API contract and that an implementation error in the library caused the failure, leave the driver unchanged. Explain the evidence, and end your response with VERDICT: library_bug on its own line.

Modify only the specified driver file, treating the current file on disk as authoritative. Library source and build configuration are for inspection only.
Do not compile or run it yourself; the workflow will verify it. Save the repair directly to the file; do not repeat the complete code block.
Place VERDICT on the last nonempty line and output it only once.
"""


REPAIR_CONTINUATION_PROMPT = """Continue based on the current source code and the latest diagnostics.

Use the current fuzz driver as the baseline. Fix only errors supported by clear evidence; do not redesign the test scenario.

Repair mode: {repair_mode}
Driver file path: {driver_file}

### Current driver source code

```cpp
{driver_code}
```

### Latest {diagnostic_label}

```
{error_message}
```

{artifact_section}
{closing_instruction}"""

REPAIR_CONTINUATION_CLOSING = {
    "compile": (
        "If necessary, consult the public declarations and source code of the current library version, and use Edit to repair the specified file directly. "
        "Do not compile or run it yourself; the workflow will verify it. Briefly describe the change in your response; do not repeat the complete code block."
    ),
    "runtime": (
        "Reassess the failure attribution from the latest diagnostics: for a driver error, use Edit to repair the specified file; for a library defect, leave the file unchanged. "
        "Briefly describe the evidence and end your response with VERDICT: driver_fault or VERDICT: library_bug on its own line. "
        "Do not compile or run it yourself; do not repeat the complete code block."
    ),
}


_REPAIR_PROMPTS = {
    "compile": COMPILE_REPAIR_PROMPT_TEMPLATE,
    "runtime": RUNTIME_REPAIR_PROMPT_TEMPLATE,
}


def get_repair_prompt_template(repair_mode: str) -> str:
    """返回当前修复模式的完整提示词。"""
    try:
        return _REPAIR_PROMPTS[repair_mode]
    except KeyError as exc:
        valid = ", ".join(sorted(_REPAIR_PROMPTS))
        raise ValueError(
            f"Unsupported repair mode '{repair_mode}'. Expected one of: {valid}"
        ) from exc
