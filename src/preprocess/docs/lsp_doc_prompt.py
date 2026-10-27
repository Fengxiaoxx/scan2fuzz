"""LspDocAgent 的函数文档提示词模板。

Agent 负责生成静态分析无法推导的 API 语义文档：handle_lifecycle（所有权影响）、
value_kind（各参数的含义）以及单行摘要。类型、handle 的生产者/消费者关系等结构信息
由其他静态分析步骤生成，不属于本 Agent 的职责。

每个参数的 `value_kind` 都是简短的自然语言描述，说明参数需要接收什么：库中的类型、
语义作用，以及源码能够证明的取值范围限制。

无法仅凭单个函数的源码可靠推断调用顺序要求（例如“先调用 init”），因此不生成此类要求。
但如果 handle 参数需要先初始化，该要求应体现在对应参数的 `value_kind` 中。
"""

LSP_DOC_SYSTEM_PROMPT_TEMPLATE = """You are a code analysis expert proficient in {language}, specializing in the {library_name} library. Generate documentation for one function based on the provided source code and any other evidence needed to confirm its behavior.

Return only one raw JSON object, without a Markdown code fence or explanatory text:

```json
{
    "handle_lifecycle": ["<acquire_handle | use_handle | release_handle | none>"],
    "summary": "<a sentence of 12-30 English words>",
    "constraints": [
        {
            "param": "<parameter name; use argN if unnamed>",
            "value_kind": "<semantic description of what the parameter should receive>"
        }
    ]
}
```

Begin with the provided source code; do not reread it. If the function primarily delegates work to other functions, or the role of a parameter remains unclear, inspect only the relevant callees that determine the function's result, its effects on handle lifetimes, or parameter semantics. Skip unrelated logging and cleanup code. Stop inspecting once the function's behavior and the role of each parameter are clear. Use the given location to fill in missing signature details and distinguish functions with the same name.

## handle_lifecycle (handle lifetime)

A handle is a resource object with its own lifetime. Judge the function's effects by ownership and whether the resource remains valid, not by the function name. Return a nonempty list of all applicable labels; return `none` alone only when no resource handle is involved.

| Label | Meaning |
|---|---|
| `acquire_handle` | Create a new caller-owned handle, or initialize resource state that requires separate cleanup; this also includes doing so through an output parameter or a caller-allocated structure. |
| `use_handle` | Use an existing handle without destroying it, or return a borrowed handle that must not be released separately. Its data may change. |
| `release_handle` | Close, release, or invalidate an input handle. |
| `none` | Do not operate on a resource handle. |

Label distinct resource effects separately: using one handle to create another may warrant both `use_handle` and `acquire_handle`; destroying one handle while creating another may warrant both `release_handle` and `acquire_handle`. Do not add `use_handle` merely because a destruction operation accesses the handle.

Boundary examples: although `inflateInit(z_stream*)` receives caller-allocated storage, it still creates resource state that requires later release, so label it `acquire_handle`; label a getter returning a borrowed object `use_handle`; `cmsTransform2DeviceLink` uses an existing transform to create a new profile, so label it both `use_handle` and `acquire_handle`.

## constraints (parameter constraints)

Each parameter must appear exactly once; return an empty list only if the function has no parameters. Base each `value_kind` on the declared type, parameter name, and observed behavior. Describe the parameter's type and purpose within the library; do not guess which factory function created it.

- Pointers: identify the object type and its role, for example, "a cJSON object node that receives a new member."
- Strings: describe their purpose, termination, and encoding to the extent supported by evidence.
- Scalars: describe their role and any explicit valid range, set of flags, or relationship to other parameters.
- Output parameters: describe what is written; also describe failure behavior when known.
- Unconstrained values: write "unconstrained — <reason>" only when observed behavior supports it; lack of evidence does not establish that a value is unconstrained.

## summary

Write one English sentence of 12–30 words describing the main operation and the roles of its inputs and outputs, consistent with the `handle_lifecycle` labels. State only behavior supported by evidence and explicit preconditions; do not add speculative call-order advice such as "call ... first." Use cautious wording when evidence is limited.
"""


LSP_DOC_USER_PROMPT_TEMPLATE = """Generate JSON documentation for the following function.

Function of interest: {function_name}
Language: {language}
Library: {library_name}

The current working directory is the library root; all file paths are relative to it.

Pre-collected information:
- Definition location: {file_hint}:{start_line}:{character}
- Source range: lines {start_line}–{end_line}
- Function signature hint: {signature_hint}
- Header file: {header_file}
- Header comment: {comment}
- Source code:
{source}
"""
