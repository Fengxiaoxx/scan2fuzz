# Scan2Fuzz

Scan2Fuzz 是面向 C/C++ 库的研究原型：将代码审计或静态分析产生的目标位置转换为 libFuzzer 驱动，经过编译修复、运行时检查和目标行覆盖测量后，将合格驱动合并为 AFL++ 测试程序。

当前主流程为：

```text
scan → preprocess → driver_rounds → fuzz_run
```

本文对应当前 `src/cli/` 实现。服务器部署见 [Docker 部署说明](docker/README.md)。

## 代码与目录

| 路径 | 职责 |
| --- | --- |
| `src/cli/` | 命令行入口、阶段编排、并发参数和 run 配置绑定 |
| `src/scan/` | 分析构建、扫描后端、告警规范化及证据保存 |
| `src/preprocess/` | 公共 API 提取、调用关系、API 文档、事实库和向量索引 |
| `src/driver_generation/` | 根据候选 API 和目标位置生成驱动 |
| `src/compile_repair/` | 编译诊断修复和运行时崩溃归因、修复 |
| `src/driver_refinement/` | 根据覆盖反馈调整驱动以提高目标可达性 |
| `src/driver_qualification/` | libFuzzer 运行、覆盖测量、停滞判断和结果存储 |
| `src/target_reachability/` | 对外的目标可达性接口，复用 `driver_qualification` 实现 |
| `src/driver_rounds/` | 以目标为单位推进候选驱动状态机 |
| `src/fuzz_run/` | 合格驱动筛选、合并构建、selector 种子和 AFL++ 运行 |
| `src/llm/`、`src/tools/`、`src/knowledge/` | OpenCode 接入、工具调用、模型用量及语义检索 |
| `src/core/`、`src/experiment/`、`src/ui/` | 配置与通用工具、run 存储与汇总、终端进度界面 |
| `tests/` | `unittest` 测试类和 pytest 风格函数测试 |
| `info_lib/<lib>/config.yaml`、`build.sh` | 每个库的配置及构建配方 |
| `test_lib/<lib>/` | 下载的目标库源码；不随主仓库提交 |
| `workspace/<lib>/` | run、独立构建和测试产物；不随主仓库提交 |
| `docker/`、`scripts/` | 部署、自检、工具链准备和实验辅助脚本 |
| `ablations/`、`docs/`、`results/`、`paper/`、`papers/` | 本地可选的实验和论文资料，不属于主程序的运行依赖 |

`info_lib/<lib>/` 中的 `raw/`、`txt/`、`api/`、`external/` 等目录是共享工作产物；追溯具体实验时，应读取 `workspace/<lib>/runs/<run_id>/` 中的快照。

## 环境准备

推荐使用根目录的 [Dockerfile](Dockerfile) 和 [compose.yaml](compose.yaml)。镜像内的主要工具为：

| 工具 | 当前环境中的用途 |
| --- | --- |
| Python 3.11、[requirements.txt](requirements.txt) | 主程序及 Python 依赖，包括 CMake、tree-sitter、FAISS |
| Clang/LLVM 15 | 库与驱动编译、libFuzzer、覆盖数据处理 |
| LLVM 18 | bitcode 链接和两个原生分析工具的构建 |
| clangd 20.1.8 | API 声明、头文件和签名解析 |
| CodeQL CLI 2.25.4 | 分析数据库和结构查询；静态告警后端也使用它 |
| Infer 1.2.0 | `codeql-infer` 告警后端 |
| OpenCode 1.18.35、ripgrep | 模型会话和原生文件检索 |
| AFL++ 4.33c | 最终合并驱动的测试；由准备脚本另行安装 |

版本以 Dockerfile、requirements.txt 和 `scripts/setup_comparison_aflpp.sh` 为准。即使选择默认的 `unit-audit` 后端，仍需要 CodeQL 构建数据库并执行结构查询。

在仓库根目录执行：

```bash
cp env.template .env
# 编辑 .env，填写模型服务、模型名及密钥

docker compose build trace2fuzz
docker compose up -d --wait
docker compose exec trace2fuzz python3 docker/selfcheck.py
docker compose exec trace2fuzz bash
```

默认只启动运行容器，使用 `.env` 中的外部嵌入服务，无需本地 GPU。仓库挂载到 `/Trace2Fuzz`，源码和运行产物保存在宿主目录；镜像只包含应用代码和环境输入，不包含下载的库、实验数据或凭据。后续 Python 命令均在仓库根目录、配置好的运行环境中执行。

自检会调用嵌入服务、检查模型服务或登录状态，并发起一次真实 OpenCode 请求。需要代理时使用 `T2F_PROXY` 和 `T2F_NO_PROXY`；容器访问宿主服务可使用 `host.docker.internal`。

### 可选：本地嵌入服务

将 Qwen3-Embedding-8B 权重放到 `models/Qwen3-Embedding-8B/`，或通过 `EMBEDDING_WEIGHTS_DIR` 指定已有权重目录。在 `.env` 中设置：

```dotenv
EMBEDDING_API_BASE="http://embedding:8000/v1"
EMBEDDING_MODEL="qwen3-embedding-8b"
EMBEDDING_API_KEY="<本地服务访问令牌>"
```

然后构建并启动可选 profile：

```bash
docker compose --profile local-embedding build
docker compose --profile local-embedding up -d --wait
```

该镜像在构建时复制权重，需要 NVIDIA GPU 和可用的 GPU 容器环境。显卡、显存比例和端口等可选设置见 [compose.yaml](compose.yaml) 和 [Docker 部署说明](docker/README.md)；需要覆盖默认值时自行追加到 `.env`。

## 配置

### 模型与嵌入服务

[env.template](env.template) 只保留模型和嵌入服务的六个必要字段，不预设供应商、外部服务地址或模型。下文的可选参数按需追加到 `.env`。使用自部署或其他 Chat Completions 兼容服务时，只需填写地址、密钥和模型名，无需设置 `LLM_PROVIDER`：

```dotenv
LLM_BASE_URL="http://host.docker.internal:8000/v1"
LLM_API_KEY='["<服务访问令牌>"]'
LLM_MODEL="<服务实际提供的模型名>"

EMBEDDING_API_BASE="<嵌入服务基础地址>"
EMBEDDING_API_KEY="<嵌入服务密钥>"
EMBEDDING_MODEL="<嵌入模型名>"
```

`LLM_BASE_URL` 填基础地址，不包含 `/chat/completions`。省略 `LLM_PROVIDER` 时，代码自动使用通用标识 `trace2fuzz_custom`。模型服务需要支持流式输出、工具调用，并有足够的上下文容量，部署细节见 Docker 文档。

| 变量 | 用途 |
| --- | --- |
| `LLM_MODEL` | 全局模型名 |
| `UNIT_AUDIT_MODEL` | `unit-audit` 扫描模型，可覆盖全局模型 |
| `API_DOC_MODEL` | API 文档生成模型 |
| `DRIVER_GEN_MODEL` | 驱动生成模型 |
| `FIX_AGENT_MODEL` | 编译修复和运行时归因、修复模型 |
| `REFINER_AGENT_MODEL` | 可达性调整模型 |
| `OPENCODE_REASONING_EFFORT` | 推理强度；默认 `high`，可选值取决于模型 |
| `OPENCODE_TEMPERATURE` | 未显式指定温度的会话使用此值；编译修复显式使用 `0` |
| `EMBEDDING_BATCH_SIZE` | 索引构建每批文档数；默认 `20` |

模型名通常按“阶段覆盖值 → `LLM_MODEL` → 代码默认值”解析，但创建 run 时必须能解析出四个下游阶段模型以及嵌入服务地址、模型名；建议明确设置 `LLM_MODEL`。切换全局模型时，也要清理旧的阶段覆盖值。

每次模型请求启动隔离的 OpenCode 服务。自定义服务的凭据从 `.env` 或当前环境读取；`LLM_API_KEY` 接受单个字符串或 JSON 密钥列表。多密钥按每个进程的并发预算均衡分配，并记录不含密钥值的重试和冷却事件；单密钥直接连接。不同库的进程分别维护自己的密钥池。

项目也支持 OpenCode 保存的 ChatGPT 登录：显式设置 `LLM_PROVIDER=openai` 和 `LLM_MODEL`，清空 `LLM_BASE_URL`、`LLM_API_KEY`，再执行 `docker compose exec -it trace2fuzz opencode auth login`。可用模型通过 `opencode models openai` 查询；Compose 的 `opencode-login` 卷保存登录信息。

嵌入服务用于 FAISS 语义检索，构建和查询都发送原始文本。更换嵌入模型或向量维度后，需要重建对应索引；仅更换生成模型不要求重建嵌入索引。

### 库配置与源码

每个库至少需要：

```text
test_lib/<lib>/              独立的源码 Git checkout
info_lib/<lib>/config.yaml   语言、链接配置、可达性运行时间等
info_lib/<lib>/build.sh      构建入口
```

可用 `bash download_benchmark.sh <lib>` 准备脚本支持的库；不带参数会准备脚本列出的全部库。具体版本和额外依赖由下载脚本与各库构建脚本决定。

配置格式由 [src/core/config.py](src/core/config.py) 校验，示例见 [lcms 配置](info_lib/lcms/config.yaml)：

- `language`：`c` 或 `cpp`。
- `compile_config`：`analysis_library`、`sanitize_library`、`coverage_library` 和 `additional_libs`。
- `driver_qualification`：正整数 `chunk_seconds`、`max_total_time`。
- 可选 `public_api`：入口头文件、语言标准、安装头文件的额外 include 子目录等。
- 可选 `unit_audit.exclude_installed_header_prefixes`：排除非本库的安装头文件前缀。

构建变体为 `analysis`、`sanitize`、`coverage`、`aflpp`。新 run 的驱动使用 scan 冻结的安装公共头文件。扫描要求源码树与其独立 Git checkout 一致；允许的流水线目录和 Git 忽略的 autotools 引导产物规则见 [source_tree.py](src/scan/source_tree.py)。

## Pipeline Commands

### 阶段职责

| 阶段 | 主要工作及下游输入 |
| --- | --- |
| `scan` | 构建分析库、安装公共头文件、CodeQL 数据库和 bitcode；执行一个告警后端，冻结目标及结构证据 |
| `preprocess` | 从公共 API、LLVM 直接调用关系及 CodeQL 绑定证据构建调用图、候选计划、API 文档、事实库和向量索引 |
| `driver_rounds` | 独立推进每个目标的生成、编译、可达性测量、崩溃处理和调整 |
| `fuzz_run` | 筛选合格驱动，合并为 ASan+UBSan AFL++ 程序并运行测试 |

默认告警后端为 `unit-audit`，通过 tree-sitter 枚举函数、分片并交给模型审计。也可显式选择 `codeql-infer`；两个后端互斥，不合并告警。当前结构分析使用 LLVM 原生提取器和 CodeQL，不依赖 SVF；下游候选输入为 `candidate_plan.json`。

### 运行入口

```bash
# 查看阶段及实际命令，不创建 run
python3 -m src.cli.pipeline <lib> --list

# 完整流程；会进入最终 AFL++ 阶段
python3 -m src.cli.pipeline <lib>

# 只完成驱动生成与验证
python3 -m src.cli.pipeline <lib> --to driver_rounds

# 只扫描，或完成扫描和预处理
python3 -m src.cli.pipeline <lib> --only scan
python3 -m src.cli.pipeline <lib> --to preprocess
```

`scan` 创建 run 并打印 `Run ID`。各阶段也可以独立执行，后续阶段必须使用同一 run：

```bash
python3 -m src.cli.scan <lib>
python3 -m src.cli.preprocess <lib> --run-id <run_id>
python3 -m src.cli.driver_rounds <lib> --run-id <run_id>
python3 -m src.cli.fuzz_run_stage <lib> --run-id <run_id>
```

阶段参数通过 `--stage-args '阶段=参数'` 传递，可重复使用。完整参数以各入口的 `--help` 为准。

### 并发与时间预算

| 参数 | 默认值 | 作用范围 |
| --- | --- | --- |
| pipeline 的 `--concurrency` | `4` | 传给 scan、preprocess、driver_rounds 的模型任务及同时请求数 |
| `--fuzz-concurrency` | 当前可用 CPU 数 | driver_rounds 的可达性 fuzzer 池；独立于模型池 |
| fuzz_run 的 `--concurrency` | `4` | 最终 AFL++ 同时运行的重复实验数 |
| fuzz_run 的 `--repetitions` | `10` | 最终独立实验次数 |
| fuzz_run 的 `--seconds-per-run` | `86400` | 每次最终实验时长，单位秒 |
| fuzz_run 的 `--timeout-ms` | `5000` | 最终实验的单输入超时，单位毫秒 |

每个可达性 fuzzer 最多使用约 2560 MB 内存，应按可用内存调整 `--fuzz-concurrency`。pipeline 的 `--concurrency` 不会传给最终阶段；最终阶段的设置需通过 `--stage-args 'fuzz_run=...'` 单独传递。可达性探测时间由库配置的 `driver_qualification` 控制。

### 续跑与配置快照

run 创建时保存 `config/config.yaml`、`config/build.sh` 和 `config/agent-env.json`。模型 provider、基础地址、全局模型、四个下游阶段模型及嵌入地址、模型名会冻结；API 密钥从当前环境读取，不写入该快照。修改 `.env` 不会覆盖已有 run 的这些设置，切换配置应创建新 run。

`UNIT_AUDIT_MODEL`、`OPENCODE_REASONING_EFFORT`、`OPENCODE_TEMPERATURE` 和 `EMBEDDING_BATCH_SIZE` 当前不在冻结字段中，复现实验时需要另外保持一致。

续跑必须显式从第一个待执行阶段开始，例如 scan 已完成时：

```bash
python3 -m src.cli.pipeline <lib> --run-id <run_id> --from preprocess
```

程序不会自动跳过选中范围内已有 `result.json` 的阶段，而是拒绝覆盖；也会检查直接前置阶段的结果。没有 scan 目标时流程直接结束，没有 `REACHED` 驱动时最终阶段写入 `skipped`。

中断但未写入阶段结果时，可复用同一 run 的已有检查点；unit-audit 只复用与请求摘要匹配的成功切片，driver_rounds 从追加的目标事件恢复。若失败阶段已经写入 canonical `result.json`，它也会阻止重跑；需先检查诊断并归档该结果，再明确重试。不要删除整个 run 或覆盖既有证据。同一个库受运行锁保护，不同库可以并行。

最终阶段会保存 `plan.json`，未完成时重试要求参数一致。其 `campaign.json` 仅在整次 campaign 完成后写入；没有此检查点时重试会创建新的 campaign 目录，不会续接上一次 AFL++ 进程。

## 驱动状态与结果含义

每个目标独立遍历候选 API：

```text
READY_GENERATE → READY_COMPILE → READY_REACH
                                  ├─ 命中 → REACHED
                                  ├─ 未命中 → READY_REFINE → READY_COMPILE
                                  └─ 崩溃 → READY_TRIAGE
                                             ├─ 库问题 → CRASH
                                             └─ 驱动修复 → READY_COMPILE

候选失败 → 下一候选的 READY_GENERATE；候选耗尽 → EXHAUSTED
没有静态候选 → UNRESOLVED_STATIC
```

`REACHED` 表示实际测到目标行命中；`CRASH` 表示 Repair Agent 将崩溃归因为库问题，需要结合保存的证据复核。静态调用链本身不代表运行时命中。

生成失败、编译修复、运行时修复和可达性调整的默认候选预算分别为 5 次，其中编译与运行时修复独立计数。基础设施失败单独记录并重试，不消耗候选预算；每次命令的基础设施重试预算由 `--max-infrastructure-retries` 控制，默认 5。调整后的驱动通过无崩溃的探测后才会成为稳定版本，失败会回滚。

驱动生成通过 OpenCode 原生 `read`、`grep`、`glob` 读取上下文，并通过 `find_api` 查询辅助 API。提示词、编译诊断、覆盖反馈和模型用量保存在 run 中，便于分析各次尝试。

## 产物与日志

```text
workspace/<lib>/
├── runs/<run_id>/
│   ├── run.json
│   ├── pipeline.log
│   ├── config/                     配置、构建脚本和非密钥环境快照
│   ├── stages/
│   │   ├── scan/                   目标、告警、构建与结构证据
│   │   ├── preprocess/             API、候选计划、事实库与索引
│   │   ├── driver_rounds/
│   │   │   ├── state-manifest.json
│   │   │   ├── targets/<marker>/events/event-000001.json
│   │   │   └── result.json
│   │   ├── driver_generation/<driver_id>/
│   │   ├── compile_repair/<driver_id>/
│   │   ├── target_reachability/<driver_id>/
│   │   ├── driver_refinement/<driver_id>/
│   │   └── fuzz_run/               最终实验计划、检查点及结果
│   ├── state/drivers/<driver_id>/   Repair 会话状态
│   └── summary/
│       ├── result.json
│       ├── metrics.json
│       └── orchestration/<invocation>/
├── fuzz_builds/<run_id>/<invocation>/
└── fuzz_runs/<run_id>/<invocation>/
```

重要文件均相对于 `runs/<run_id>/`：

| 阶段 | 主要文件 |
| --- | --- |
| scan | `stages/scan/result.json`、`targets.txt`、`findings.json`、后端报告 `unit-audit-findings.json` 或 `codeql.sarif` / `infer-report.json` |
| 分析构建 | `stages/scan/compile_commands.json`、`linked.bc`、`build-result.json`、`analysis-library/`、`public-install/include/` |
| 结构证据 | `stages/scan/reachability/` 下的 `call_graph.direct.csv`、`function_locations.csv`、`include-edges.csv`、`provenance-edges.csv`、`scope.json` |
| preprocess | `stages/preprocess/candidate_plan.json`、`structural/`、`api-doc-index.json`、`api-docs/`、`fact_base.json`、`drivers.json`、`faiss-index/` |
| driver_rounds | `stages/driver_rounds/result.json` 和 `targets/<marker>/events/` 下的目标状态事件 |
| 最终实验 | `stages/fuzz_run/plan.json`、`campaign.json`、`result.json`；完整输出位于 `workspace/<lib>/fuzz_runs/` |
| 汇总 | `summary/result.json`、`summary/metrics.json`；每次 pipeline 调用另存 `summary/orchestration/` |

各阶段日志在对应 `stages/<stage>/logs/` 下；驱动级日志在 `stages/<stage>/<driver_id>/logs/` 下。源码、二进制及探测尝试位于各驱动的阶段目录，不是顶层的 `drivers/` 目录。unit-audit 失败切片会重审，合计最多 5 轮；仍失败的切片及错误保存在报告中，scan 可能继续完成，因此 `completed` 不等于所有切片都审计成功。

阶段证据和事件按不可覆盖或追加方式保存；会话状态、检查点及 `summary/` 汇总会更新，并非 run 中所有文件都不可变。

## 独立构建与最终测试

最终阶段只选择状态为 `REACHED`、且目标命中数大于零的驱动。`CRASH` 驱动不进入合并集合；最终 AFL++ 产生的崩溃需要另行去重和归因。

```bash
# 只构建合并后的 ASan+UBSan AFL++ 程序，不启动测试
python3 -m src.cli.fuzz_build <lib> --run-id <run_id>

# 在已有 driver_rounds 结果后执行 canonical 最终阶段
python3 -m src.cli.pipeline <lib> --run-id <run_id> --only fuzz_run

# 独立运行 campaign，不写 canonical stages/fuzz_run/result.json
python3 -m src.cli.fuzz_run <lib> --run-id <run_id>
```

`fuzz_build` 和 canonical 最终阶段会准备缺失的 AFL++ 工具及库归档；独立的 `src.cli.fuzz_run` 要求先准备这些依赖。工具链可通过 `bash scripts/setup_comparison_aflpp.sh` 安装，库归档由对应 `build.sh aflpp` 构建。准备步骤可能需要联网。

独立构建的 `build.json` 记录程序哈希、驱动 selector 映射和种子信息，位于 `fuzz_builds/<run_id>/<invocation>/`。最终阶段启动时重新构建，不复用该独立构建目录。`--driver` 可重复指定以筛选驱动。

合并程序使用一字节 selector，最多支持 256 个驱动。每个初始种子只包含 selector，不附加 payload 或库语料；合并入口在没有 payload 时直接返回，需要后续变异才能进入驱动。每次 campaign 的 `result.json` 记录映射、设置和运行结果。

独立 `fuzz_run` 另有 `--detect-leaks`，为每个输入执行 LSan 检查；canonical `fuzz_run_stage` 当前未暴露该开关。

`scripts/` 中还有实验专用辅助工具。跨工具对比的 selector 种子生成器为 `src/fuzz_run/selector_seeds.py`：PromeFuzz/Trace2Fuzz 使用一字节，PromptFuzz 使用双字节大端 selector；输出目录必须为空，不能混入元数据或已有 corpus。

## 开发检查

`requirements.txt` 提供运行依赖；完整执行测试还需安装 pytest（可同时收集 `unittest` 测试类和函数测试）：

```bash
python3 -m pip install -r requirements.txt pytest
python3 -m pytest tests -v
```

只检查命令行或阶段编排时，可运行：

```bash
python3 -m src.cli.pipeline --help
python3 -m src.cli.pipeline <lib> --list
python3 -m unittest discover -s tests -p 'test_fuzz_run_stage.py' -v
```

测试依赖的原生工具按各测试中的跳过条件处理；单元测试通过不能替代完整库构建或真实模型服务自检。
