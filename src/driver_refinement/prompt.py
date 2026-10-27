"""Prompt contract for runtime feedback guided driver refinement."""

REFINER_PROMPT_TEMPLATE = """The {library_name} libFuzzer driver did not execute the target source location {code_location} during this fuzzing run. The library source is at {library_root}.

Runtime coverage evidence:
{coverage_evidence}

Current driver:
{driver_source}

Use the runtime evidence and relevant library source to analyze why the target line was not executed. If a feasible path exists, modify the driver so the target line and related branches are on execution paths controlled by Data/Size and explorable through input mutation. You may restructure the driver or change its call path; any new calls must compile and link in the current build configuration.

Use only Edit to modify {driver_file}. Preserve the libFuzzer entry point, keep execution bounded, and manage object ownership and resource cleanup correctly. Do not modify library source or compile or run the driver yourself.

Leave the driver unchanged only if the source and build conditions prove that the target line is unreachable at runtime in this build. In that case, explain the specific fixed condition or internal invariant. Failure to execute the line in this run alone does not prove unreachability.

Return only one JSON object: {"changes":"..."}. If you edited the driver, describe the changes actually made; if you left it unchanged, explain the evidence for runtime unreachability."""


# Repeat the full contract on resumed sessions, including sessions created with
# an older prompt, so later rounds use the same edit and response rules.
REFINER_FOLLOWUP_MESSAGE = REFINER_PROMPT_TEMPLATE
