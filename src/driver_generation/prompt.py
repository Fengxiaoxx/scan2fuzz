"""Driver 生成 Agent 使用的提示词模板。"""

DRIVER_GENERATION_PROMPT_TEMPLATE = """Write a complete, compilable libFuzzer driver for the {language} library {library_name}. Use the public entry API {target_api} to fuzz the specified internal code line and determine whether that line contains a vulnerability whose type is {vulnerability_type}. The driver should enable execution to cover the line and explore the behavioral space around it.

## 1. Context

- Available header files:
{headers}
- Entry API (the driver's call entry point): {target_api}, defined in {defined_in}
  - Signature: {signature}
- Entry API source code:
```c
{api_source}
```
- Code line to cover (through an execution path from the entry API):
{target_lines}

- The vulnerability type above is for analyzing possible causes; it does not represent a known triggering condition.

## 2. Auxiliary tools

If {target_api} alone cannot perform initialization, construct the prerequisite state, or release resources, first use find_api to retrieve the public interfaces of {library_name} and verify their calling contracts from public declarations, documentation, or implementations. If necessary, use the file tools (Read/Grep) to inspect library source and header files. Do not call non-public internal functions or invent APIs that do not exist.

## 3. Generation criteria

### A. Path guidance and input mapping (reachability & input mapping)

1. Analyze possible causes: analyze the control flow, data flow, object provenance, and lifetimes from {target_api} to the code line, and use the vulnerability type to identify parameters and states that may affect behavior there. All such judgments are hypotheses to be verified and serve only to identify dimensions for the fuzz input to explore.
2. Construct a searchable path: construct initialization states, configurations, and prerequisite parameters that satisfy the public API contract so execution can reach the code line. Parameters and states related to possible causes and expressible through public APIs should be driven by Data/Size, while preserving ordinary values, boundary values, and multiple valid states. **Never fix any hypothesis as a specific triggering value, a narrow value range, or a single object and call scenario. Even if the causal hypothesis is wrong, the driver must still be able to explore other valid states near the specified location; otherwise, the driver is unacceptable.**
3. Consume input safely: prefer the FuzzedDataProvider provided by `#include <fuzzer/FuzzedDataProvider.h>` to safely extract scalars, flags, and byte streams from Data/Size. If reading Data directly by offset, check the remaining length before every read. Set reasonable limits on input-derived allocation sizes, container reserve capacities, and loop counts.

### B. API contracts and resource lifetimes

- Create, use, and release library objects only through public APIs; follow object ownership and cleanup rules.
- Check for initialization and allocation failures. Before exiting, including on error-return paths, release all allocated memory, handles, and contexts in the correct order. The harness itself must have no leaks.

### C. Entry point and robustness

- The entry-point signature must match exactly (the driver is compiled as a C++ source file, and the entry point requires extern "C" linkage):
  {entry_signature}
- The first line must reject empty input: `if (!Data || Size == 0) return 0;`
- Prefer in-memory buffer APIs. When a file is necessary, use a fixed basename; never derive a path from fuzz input.

## 4. Output format

After completing any necessary tool queries, when producing the final code, output only one cpp or c code block containing the complete driver source. Do not include a preface, explanation, or summary."""
