# Scan2Fuzz

Scan2Fuzz is a research prototype for C/C++ libraries. It turns source locations
reported by code audits or static analysis into libFuzzer drivers, checks their
compilation and runtime behavior, measures target coverage, and merges qualified
drivers into an AFL++ executable.

The pipeline is:

```text
scan → preprocess → driver_rounds → fuzz_run
```

This document describes the current implementation in [src/cli](src/cli).

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/cli/` | Command-line entry points, stage orchestration, concurrency, and run configuration |
| `src/scan/` | Analysis builds, scan backends, finding normalization, and evidence storage |
| `src/preprocess/` | Public APIs, call relationships, API documentation, fact bases, and vector indexes |
| `src/driver_generation/` | Driver generation from candidate APIs and target locations |
| `src/compile_repair/` | Compilation repair, runtime failure attribution, and driver repair |
| `src/driver_refinement/` | Driver refinement using target coverage feedback |
| `src/driver_qualification/` | libFuzzer execution, coverage measurement, progress monitoring, and artifacts |
| `src/target_reachability/` | Target reachability interface backed by `driver_qualification` |
| `src/driver_rounds/` | Per-target driver state machines |
| `src/fuzz_run/` | Qualified driver selection, merged builds, selector seeds, and AFL++ execution |
| `src/llm/`, `src/tools/`, `src/knowledge/` | OpenCode integration, tools, model usage, and semantic retrieval |
| `src/core/`, `src/experiment/`, `src/ui/` | Shared configuration, run storage, summaries, and terminal progress |
| `info_lib/<lib>/config.yaml`, `build.sh` | Library configuration and build recipes |
| `test_lib/<lib>/` | Locally prepared library source checkouts; excluded from Git |
| `workspace/<lib>/` | Run artifacts, standalone builds, and campaign results; excluded from Git |

Generated directories such as `info_lib/<lib>/raw/`, `txt/`, `api/`, and
`external/` contain shared working data. Use the snapshots under
`workspace/<lib>/runs/<run_id>/` when tracing a particular experiment.

The repository includes configurations for these 12 libraries:
`abseil-cpp`, `c-ares`, `cJSON`, `curl`, `lcms`, `libaom`, `libjpeg-turbo`,
`liblouis`, `nghttp2`, `re2`, `sqlite3`, and `zlib`.

## Environment

The root [Dockerfile](Dockerfile) and [compose.yaml](compose.yaml) define the
runtime environment. Its main dependencies are:

| Tool | Purpose |
| --- | --- |
| Python 3.11 and [requirements.txt](requirements.txt) | Runtime dependencies, including CMake, tree-sitter, and FAISS |
| Clang/LLVM 15 | Library and driver compilation, libFuzzer, and coverage processing |
| LLVM 18 | Bitcode linking and compilation of the native analysis tools |
| clangd 20.1.8 | API declarations, headers, and signatures |
| CodeQL CLI 2.25.4 | Analysis databases and structural queries; also used by the static alert backend |
| Infer 1.2.0 | The `codeql-infer` alert backend |
| OpenCode 1.18.35 and ripgrep | Model sessions and native source retrieval |
| AFL++ 4.33c | Final merged-driver campaigns; installed separately when needed |

Exact versions are defined in the Dockerfile, requirements file, and
[AFL++ setup helper](src/fuzz_run/setup_aflpp.sh). CodeQL is required even with
the default `unit-audit` backend because it builds databases and supplies
structural queries.

From the repository root:

```bash
cp env.template .env
# Fill in the model endpoints, model names, and credentials in .env.
docker compose build trace2fuzz
docker compose up -d --wait
docker compose exec trace2fuzz bash
```

The default Compose configuration starts the runtime container and uses the
external embedding endpoint configured in `.env`. This configuration does not
require a local GPU. The repository is mounted at `/Trace2Fuzz`, so library
sources and generated artifacts persist on the host. Downloaded libraries,
experiment data, and credentials are excluded from the runtime image.

Run the Python commands below from the repository root inside the prepared
environment. Optional proxy settings are `T2F_PROXY` and `T2F_NO_PROXY`.
Containers can reach services on the Docker host through `host.docker.internal`.

### Optional local embeddings

Place Qwen3-Embedding-8B weights in `models/Qwen3-Embedding-8B/`, or set
`EMBEDDING_WEIGHTS_DIR` to an existing weight directory. Configure:

```dotenv
EMBEDDING_API_BASE="http://embedding:8000/v1"
EMBEDDING_MODEL="qwen3-embedding-8b"
EMBEDDING_API_KEY="<local-service-token>"
```

Then build and start the optional profile:

```bash
docker compose --profile local-embedding build
docker compose --profile local-embedding up -d --wait
```

The embedding image is defined inline in `compose.yaml` and copies the weights
into the image during the build. It requires an NVIDIA GPU and a working GPU
container runtime. See Compose for optional GPU selection, memory utilization,
model length, port, and base-image settings.

## Configuration

### Model and embedding services

[env.template](env.template) contains the six required fields without selecting
a provider or model. Supply a Chat Completions-compatible endpoint and an
embedding endpoint:

```dotenv
LLM_BASE_URL="<chat-api-base-url>"
LLM_API_KEY="<chat-api-key>"
LLM_MODEL="<model-id>"

EMBEDDING_API_BASE="<embedding-api-base-url>"
EMBEDDING_API_KEY="<embedding-api-key>"
EMBEDDING_MODEL="<embedding-model-id>"
```

`LLM_BASE_URL` is the API base URL, without `/chat/completions`. No provider ID
is needed: the code uses `trace2fuzz_custom` when `LLM_PROVIDER` is omitted.
The model service must support streaming, tool calls, and a context window
large enough for the requested tasks.

Optional overrides can be added to `.env`:

| Variable | Purpose |
| --- | --- |
| `LLM_MODEL` | Global model selection |
| `UNIT_AUDIT_MODEL` | Override for the `unit-audit` scan model |
| `API_DOC_MODEL` | API documentation model |
| `DRIVER_GEN_MODEL` | Driver generation model |
| `FIX_AGENT_MODEL` | Compilation repair, runtime attribution, and repair model |
| `REFINER_AGENT_MODEL` | Reachability refinement model |
| `OPENCODE_REASONING_EFFORT` | Reasoning effort; defaults to `high`, with accepted values depending on the model |
| `OPENCODE_TEMPERATURE` | Temperature for sessions without an explicit value; compilation repair explicitly uses `0` |
| `EMBEDDING_BATCH_SIZE` | Documents per indexing batch; defaults to `20` |

Model selection generally follows a stage override, then `LLM_MODEL`, then a
code default. Creating a run requires resolvable models for the four downstream
agent roles, plus the embedding base URL and model. Set `LLM_MODEL` explicitly
and remove stale stage overrides when changing the global model.

Each model request starts an isolated OpenCode service. Credentials are read
from `.env` or the process environment. `LLM_API_KEY` accepts a single string
or a JSON list of keys. With multiple keys, requests share the process's
concurrency budget across key slots, with retry and cooldown events recorded
without credential values. Processes for different libraries maintain separate
key pools.

An OpenCode ChatGPT login is also supported. Explicitly set
`LLM_PROVIDER=openai` and `LLM_MODEL`, leave `LLM_BASE_URL` and `LLM_API_KEY`
empty, and run `opencode auth login` inside the runtime container. Use
`opencode models openai` to inspect available models. The Compose
`opencode-login` volume persists the login separately from the repository.

Embeddings power FAISS semantic retrieval. Raw text is sent both when building
and querying an index. Rebuild the affected indexes after changing the
embedding model or vector dimension. Changing only the generation model does
not require rebuilding embedding indexes.

### Library sources and recipes

Prepare each library as its own Git checkout under `test_lib/`, using the
revision required by your experiment. Library sources are obtained separately.
Each configured library needs:

```text
test_lib/<lib>/              Independent source Git checkout
info_lib/<lib>/config.yaml   Language, link settings, and runtime budgets
info_lib/<lib>/build.sh      Build entry point
```

Additional source dependencies are determined by each build recipe. For
example, the re2 recipe uses the sibling `abseil-cpp` checkout, and nghttp2
requires its submodules.

The schema is validated by [src/core/config.py](src/core/config.py). See the
[lcms configuration](info_lib/lcms/config.yaml) for an example:

- `language`: `c` or `cpp`.
- `compile_config`: `analysis_library`, `sanitize_library`, `coverage_library`,
  and `additional_libs`.
- `driver_qualification`: positive integers `chunk_seconds` and `max_total_time`.
- Optional `public_api`: entry headers, language standard, and additional
  include subdirectories for installed headers.
- Optional `unit_audit.exclude_installed_header_prefixes`: installed-header
  prefixes to exclude from this library's public API.

Build variants are `analysis`, `sanitize`, `coverage`, and `aflpp`. Drivers in
new runs use the installed public headers frozen by the scan stage. Scanning
requires the source tree to match its independent Git checkout. Allowed
pipeline outputs and ignored autotools bootstrap files are defined in
[source_tree.py](src/scan/source_tree.py).

## Pipeline commands

| Stage | Work and downstream inputs |
| --- | --- |
| `scan` | Analysis library, installed public headers, CodeQL database, and bitcode; one alert backend; frozen targets and structural evidence |
| `preprocess` | Public APIs, structural call graphs, candidate plans, API documentation, fact bases, and vector indexes |
| `driver_rounds` | Independent generation, compilation, reachability measurement, crash handling, and refinement for each target |
| `fuzz_run` | Qualified driver selection, merged ASan+UBSan AFL++ build, and campaigns |

The default alert backend is `unit-audit`, which enumerates functions using
tree-sitter and submits slices for model auditing. Alternatively, select
`codeql-infer`. The backends are mutually exclusive. Structural analysis uses
native LLVM extractors and CodeQL; it does not depend on SVF. Downstream
candidate information is stored in `candidate_plan.json`.

```bash
# List stages and commands without creating a run.
python3 -m src.cli.pipeline <lib> --list

# Run the complete pipeline, including the final AFL++ stage.
python3 -m src.cli.pipeline <lib>

# Stop after driver generation and qualification.
python3 -m src.cli.pipeline <lib> --to driver_rounds

# Run only scanning, or scanning followed by preprocessing.
python3 -m src.cli.pipeline <lib> --only scan
python3 -m src.cli.pipeline <lib> --to preprocess
```

The scan stage creates a run and prints its run ID. Stages can also be invoked
individually; downstream stages must use the same run:

```bash
python3 -m src.cli.scan <lib>
python3 -m src.cli.preprocess <lib> --run-id <run_id>
python3 -m src.cli.driver_rounds <lib> --run-id <run_id>
python3 -m src.cli.fuzz_run_stage <lib> --run-id <run_id>
```

Use repeatable `--stage-args 'STAGE=ARGS'` options to forward arguments to a
particular stage. Each entry point's `--help` documents its complete options.

### Concurrency and time budgets

| Option | Default | Scope |
| --- | --- | --- |
| Pipeline `--concurrency` | `4` | Model tasks and simultaneous requests in scan, preprocess, and driver rounds |
| `--fuzz-concurrency` | Available CPU count | Reachability fuzzer pool in driver rounds, independent of model concurrency |
| Final-stage `--concurrency` | `4` | Concurrent final AFL++ repetitions |
| Final-stage `--repetitions` | `10` | Number of independent campaigns |
| Final-stage `--seconds-per-run` | `86400` | Duration of each final campaign, in seconds |
| Final-stage `--timeout-ms` | `5000` | Timeout for one input in the final campaign, in milliseconds |

Each reachability fuzzer can use approximately 2560 MB of memory. Set
`--fuzz-concurrency` according to the available memory. Pipeline
`--concurrency` does not control the final stage; use
`--stage-args 'fuzz_run=...'` for that stage's settings. Library
`driver_qualification` settings control reachability probe duration.

### Run snapshots and resuming

A new run saves `config/config.yaml`, `config/build.sh`, and
`config/agent-env.json`. The provider, base URL, global model, four downstream
agent models, and embedding endpoint/model are frozen. Credentials are read
from the current environment and are excluded from this snapshot. Create a
new run to change frozen configuration.

`UNIT_AUDIT_MODEL`, `OPENCODE_REASONING_EFFORT`, `OPENCODE_TEMPERATURE`, and
`EMBEDDING_BATCH_SIZE` are currently outside the frozen fields. Keep them
consistent when reproducing experiments.

Resume explicitly from the first pending stage. For example, after scanning:

```bash
python3 -m src.cli.pipeline <lib> --run-id <run_id> --from preprocess
```

The orchestrator refuses to overwrite a selected stage that already has a
canonical `result.json`. It also checks each stage's immediate prerequisite.
Scanning with zero targets ends the pipeline early. Without a `REACHED`
driver, the final stage records `skipped`.

Interrupted stages without a canonical result can reuse checkpoints from the
same run. Unit-audit reuses successful slices only when request digests match;
driver rounds resume from append-only target events. A failed stage that
already wrote its canonical result also blocks a retry. Inspect diagnostics
and archive that result before an explicit retry, preserving existing run
evidence. Runs for the same library are protected by a lock; different
libraries can run concurrently.

The final stage saves a `plan.json`. Retries of a pending plan must use the
same settings. It writes `campaign.json` only when the campaign completes.
Without this checkpoint, a retry creates a new campaign directory rather than
resuming the previous AFL++ process.

## Driver states and interpretation

Each target advances through candidate APIs independently:

```text
READY_GENERATE → READY_COMPILE → READY_REACH
                                  ├─ Hit → REACHED
                                  ├─ No hit → READY_REFINE → READY_COMPILE
                                  └─ Crash → READY_TRIAGE
                                              ├─ Library issue → CRASH
                                              └─ Driver repair → READY_COMPILE

Candidate failure → READY_GENERATE for the next candidate
No candidates left → EXHAUSTED
No static candidate → UNRESOLVED_STATIC
```

`REACHED` means a target-line hit was measured at runtime. `CRASH` means the
repair agent attributed a failure to the library; the stored evidence still
requires review. A static call path alone does not establish runtime coverage.

Generation, compilation repair, runtime repair, and reachability refinement
each have a default candidate budget of five attempts. Compilation and runtime
repair budgets are independent. Infrastructure failures are recorded and
retried separately without consuming candidate budgets; the default
`--max-infrastructure-retries` is five per command. A refined driver becomes
the stable version after a successful probe without a crash; unsuccessful
refinements are rolled back.

Driver generation uses OpenCode's native `read`, `grep`, and `glob` tools and
the `find_api` helper. Prompts, compiler diagnostics, coverage feedback, and
model usage are saved with the run.

## Artifacts and logs

```text
workspace/<lib>/
├── runs/<run_id>/
│   ├── run.json
│   ├── pipeline.log
│   ├── config/
│   ├── stages/
│   │   ├── scan/
│   │   ├── preprocess/
│   │   ├── driver_rounds/
│   │   │   ├── state-manifest.json
│   │   │   ├── targets/<marker>/events/event-000001.json
│   │   │   └── result.json
│   │   ├── driver_generation/<driver_id>/
│   │   ├── compile_repair/<driver_id>/
│   │   ├── target_reachability/<driver_id>/
│   │   ├── driver_refinement/<driver_id>/
│   │   └── fuzz_run/
│   ├── state/drivers/<driver_id>/
│   └── summary/
│       ├── result.json
│       ├── metrics.json
│       └── orchestration/<invocation>/
├── fuzz_builds/<run_id>/<invocation>/
└── fuzz_runs/<run_id>/<invocation>/
```

Important paths, relative to `runs/<run_id>/`, include:

| Area | Artifacts |
| --- | --- |
| Scan | `stages/scan/result.json`, `targets.txt`, `findings.json`, and backend reports such as `unit-audit-findings.json`, `codeql.sarif`, or `infer-report.json` |
| Analysis build | `stages/scan/compile_commands.json`, `linked.bc`, `build-result.json`, `analysis-library/`, and `public-install/include/` |
| Structural evidence | `stages/scan/reachability/`, including direct call edges, function locations, include/provenance edges, and scope metadata |
| Preprocess | `stages/preprocess/candidate_plan.json`, `structural/`, `api-doc-index.json`, `api-docs/`, `fact_base.json`, `drivers.json`, and `faiss-index/` |
| Driver rounds | `stages/driver_rounds/result.json` and per-target event journals |
| Final campaign | `stages/fuzz_run/plan.json`, `campaign.json`, and `result.json`; complete output is under `workspace/<lib>/fuzz_runs/` |
| Summaries | `summary/result.json`, `summary/metrics.json`, and per-invocation orchestration summaries |

Stage logs are stored under `stages/<stage>/logs/`; driver logs are under
`stages/<stage>/<driver_id>/logs/`. Sources, binaries, and probe attempts live
inside their stage directories. Unit-audit retries failed slices for up to five
rounds and preserves remaining failures in its reports. A scan marked
`completed` does not imply every slice was audited successfully.

Evidence and events are immutable or append-only, while session state,
checkpoints, and derived summaries may be updated. A summary's `completed`
status describes the stages recorded so far; confirm that `fuzz_run` has a
completed result before treating it as a completed end-to-end run.

## Standalone builds and final campaigns

The final stage selects drivers in `REACHED` state with positive target hit
counts. Drivers classified as `CRASH` are excluded. Crashes discovered by the
final campaign require separate deduplication and attribution.

```bash
# Build the merged ASan+UBSan AFL++ binary without running a campaign.
python3 -m src.cli.fuzz_build <lib> --run-id <run_id>

# Run the canonical final stage after driver rounds have completed.
python3 -m src.cli.pipeline <lib> --run-id <run_id> --only fuzz_run

# Run a standalone campaign without writing the canonical stage result.
python3 -m src.cli.fuzz_run <lib> --run-id <run_id>
```

`fuzz_build` and the canonical final stage prepare missing AFL++ tools and
library archives. The standalone `fuzz_run` entry point expects these to be
prepared already. The setup helper is `src/fuzz_run/setup_aflpp.sh`, and each
library's `build.sh aflpp` recipe produces its AFL++ archive. Preparation may
require network access.

Standalone `build.json` manifests contain the binary hash, driver-selector
mapping, and seed information under `fuzz_builds/<run_id>/<invocation>/`.
The final stage builds its own executable. Repeat `--driver` to select specific
drivers.

The merged binary uses a one-byte selector and supports up to 256 drivers.
Initial seeds contain only selectors, without payload or library corpus data.
The merged entry returns immediately when no payload is present, so mutations
are needed to enter a driver. Campaign results record the mapping, settings,
and execution results.

Standalone `fuzz_run` also exposes `--detect-leaks`, enabling an LSan check for
each input. The canonical final stage does not expose that option.

[selector_seeds.py](src/fuzz_run/selector_seeds.py) provides selector seeds for
cross-tool comparisons: PromeFuzz/Trace2Fuzz use a one-byte selector, while
PromptFuzz uses a two-byte big-endian selector. Its output directory must be
empty and contain no metadata or existing corpus files.

## Inspecting CLI options

```bash
python3 -m src.cli.pipeline --help
python3 -m src.cli.pipeline <lib> --list
```

CLI and configuration checks alone do not establish that a complete library
build, model-backed run, or final campaign has completed successfully. Inspect
the stage results and runtime evidence for the selected run.
