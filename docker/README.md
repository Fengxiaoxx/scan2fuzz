# 在 GPU 服务器上部署和运行 Trace2Fuzz

本文说明怎样把两个容器带到 GPU 服务器、接上自部署的大模型，然后跑 lcms 和 curl。
流水线各阶段和参数的完整说明见仓库根目录 `README.md` 的 “Pipeline Commands” 一节。

## 组成

| 组件 | 镜像 | 作用 |
|---|---|---|
| `trace2fuzz` | `trace2fuzz:latest`（约 5.6 GB） | 项目运行环境。仓库目录挂载为 `/Trace2Fuzz`；最终 fuzz 阶段使用本地 AFL++。 |
| `embedding` | `trace2fuzz-embedding:latest`（约 41.5 GB） | vLLM 提供 OpenAI 兼容的 `/v1/embeddings`，模型名 `qwen3-embedding-8b`，向量 4096 维。权重已在镜像里，运行时不联网。 |
| 大模型 | 自己部署 | OpenAI 兼容的 Chat Completions 服务，不在 compose 里。 |

两个容器由仓库根目录的 `compose.yaml` 定义。本页使用可选的 `local-embedding` profile：
运行容器通过 `.env` 中的 `http://embedding:8000/v1` 访问本地嵌入服务。
如果配置外部嵌入服务，直接 `docker compose up` 即可，只启动运行容器；此时需要填写外部服务的地址、模型名及真实 API key。`env.template` 不预设供应商。

## 1. 服务器准备

- NVIDIA 驱动 535 或更新（`nvidia-smi` 查看）。嵌入镜像基于 CUDA 12.9，驱动太旧时容器会被拒绝启动。
- Docker、Docker Compose v2、NVIDIA Container Toolkit。`docker run --rm --gpus all ubuntu nvidia-smi` 能列出显卡，GPU 容器就可用。
- 磁盘：镜像约 55 GB，仓库目录约 0.7 GB，另加运行产物。
- 嵌入服务需要某一张卡上有约 24 GB 空闲显存（默认占 80 GB 卡的 30%）。大模型如果占满了所有卡，要先给嵌入服务留出空间。

## 2. 把镜像和仓库带到服务器

以下命令在本机执行，`用户@服务器` 和 `/data/Trace2Fuzz` 换成实际的值。

### 镜像

```bash
docker save trace2fuzz:latest | ssh 用户@服务器 docker load
docker save trace2fuzz-embedding:latest | ssh 用户@服务器 docker load
```

网络不稳时，先 `docker save -o <文件>.tar <镜像>` 存成文件，用 `rsync -P`（可断点续传）传过去，再在服务器上 `docker load -i <文件>.tar`。

### 仓库目录

在本机仓库根目录执行：

```bash
rsync -a --info=progress2 \
  --exclude '/.git/' --exclude '/key' --exclude '/.env' --exclude '/workspace/' --exclude '/models/' \
  --exclude '/paper/' --exclude '/papers/' --exclude '/docs/' \
  --exclude '/.claude/' --exclude '/.serena/' --exclude '/.agents/' --exclude '/.codex/' --exclude '/.vscode/' \
  --exclude '__pycache__/' --exclude 'build_analysis/' --exclude 'build_sanitize/' --exclude 'build_coverage/' --exclude '.clangd' \
  --exclude '/info_lib/*/api/' --exclude '/info_lib/*/raw/' --exclude '/info_lib/*/txt/' --exclude '/info_lib/*/targets/' \
  --exclude '/info_lib/*/build/' --exclude '/info_lib/*/external/' --exclude '/info_lib/*/drivers.json' \
  --include '/test_lib/lcms/***' --include '/test_lib/curl/***' --include '/test_lib/curl-fuzzer/***' --exclude '/test_lib/*' \
  ./ 用户@服务器:/data/Trace2Fuzz/
```

传过去约 660 MB：
- 代码、`compose.yaml`、`docker/`；
- `info_lib` 下各库的配置和构建脚本；
- `test_lib` 里的 lcms、curl、curl-fuzzer，带各自的 `.git`（扫描靠它确认源码版本、检查源码树是否干净）；

不传的：
- `key`、`.env`（服务器上重新写）；
- 旧的运行产物 `workspace/`；
- 构建目录和 `info_lib` 里的生成物（每次运行都会重建）；
- 项目自己的 `.git`（流水线不需要）。

要跑别的库，再加一条 `--include '/test_lib/<库名>/***'`，它依赖的其他源码见 `info_lib/<库名>/build.sh`。

## 3. 配置 `.env`

在服务器的仓库根目录 `cp env.template .env`，然后把文件开头的大模型配置改成自部署服务的值，并设置嵌入服务的令牌：

```dotenv
LLM_BASE_URL="http://host.docker.internal:8000/v1"   # 大模型的 OpenAI 兼容地址，写到 /v1 为止
LLM_API_KEY='["<服务端的 token>"]'                    # 服务端不校验也要填一个非空值
LLM_MODEL="<服务端的模型名，即 /v1/models 返回的 id>"
EMBEDDING_API_KEY="<任意随机字符串>"                   # 嵌入服务的访问令牌
EMBEDDING_API_BASE="http://embedding:8000/v1"       # 必须与本地 profile 配套
EMBEDDING_MODEL="qwen3-embedding-8b"
```

- 无需填写 `LLM_PROVIDER`，代码会从基础地址配置自动使用通用 provider 标识。
- 大模型和容器在同一台服务器上时，容器里用 `host.docker.internal` 访问宿主；大模型服务要监听 `0.0.0.0`，不能只监听 `127.0.0.1`。
- 按阶段覆盖模型的变量（`UNIT_AUDIT_MODEL`、`API_DOC_MODEL`、`DRIVER_GEN_MODEL`、`FIX_AGENT_MODEL`、`REFINER_AGENT_MODEL`）不要设，或者都设成服务端的模型名。
- 可选设置：
  - `EMBEDDING_GPU`：嵌入服务用哪张卡，默认 0。
  - `EMBEDDING_GPU_UTIL`：嵌入服务占这张卡显存的比例，默认 0.3（80 GB 卡上约 24 GB）。40 GB 的卡设到 0.6 左右。
  - `EMBEDDING_PORT`：嵌入服务在宿主上的端口，默认 8001。
  - `T2F_PROXY`：服务器要经代理上网时设置，例如 `http://172.17.0.1:7890`。设了以后，大模型如果不是用 `host.docker.internal` 访问，
    要把它的地址加进 `T2F_NO_PROXY`（例如 `T2F_NO_PROXY=localhost,127.0.0.1,10.0.0.5`），否则大模型请求也会走代理。

### 自部署大模型的要求

- 提供 OpenAI 兼容的 `/v1/chat/completions`，支持流式输出和工具调用。审计、文档生成、驱动生成都靠 read、grep、glob 等工具调用。
  用 vLLM 部署时要加 `--enable-auto-tool-choice --tool-call-parser <该模型对应的解析器>`。
- 上下文长度：OpenCode 的每个请求都申请 32000 个输出 token，服务端的最大上下文（vLLM 的 `--max-model-len`）必须明显大于
  32000 加上提示长度。审计会话会不断累积工具输出，建议不小于 131072。上下文只有 32768 时，请求会直接被拒（HTTP 400）。
- 请求体里带有 `thinking: {"type": "enabled"}` 和 `reasoning_effort: "high"`，服务端要能接受这两个字段（vLLM v0.31 接受）。

### 改用 ChatGPT 订阅

不用自部署大模型时，可以用 OpenCode 自带的 ChatGPT Plus/Pro 登录：

1. `.env` 里只设 `LLM_PROVIDER="openai"` 和 `LLM_MODEL="<模型名>"`，**不要**设 `LLM_BASE_URL` 和 `LLM_API_KEY`。
2. 启动容器后登录一次。这一步要你本人在浏览器里授权：
   ```bash
   docker compose exec -it trace2fuzz opencode auth login
   ```
   依次选 OpenAI →「ChatGPT Pro/Plus (headless)」，在任意能上网的设备上打开它给出的链接、输入代码。
   登录信息存在 compose 的 `opencode-login` 卷里，重建容器不会丢，也不在仓库目录里。
3. 查看能用的模型：`docker compose exec trace2fuzz opencode models openai`。
   镜像里的 OpenCode 1.18.35 列出 gpt-5.4、gpt-5.5、gpt-5.6-luna/sol/terra、gpt-6-luna、gpt-6-sol、gpt-6-astra、gpt-6.1-sol 等
   （多数还有 -fast 版）；`gpt-5.3-codex` 不在订阅列表里。实际能用哪些，以你的订阅为准。
4. 推理强度和 OpenCode 客户端一样，通过模型"变体"选，默认 high。要改就在 `.env` 里设 `OPENCODE_REASONING_EFFORT`（off 等于 none）。
   可选值随模型而定：gpt-5.4、gpt-5.5 是 none 到 xhigh；gpt-5.6-*、gpt-6-luna、gpt-6-sol 是 none 到 max；
   gpt-6-astra、gpt-6.1-sol 是 low 到 max，没有 none。
   设了模型没有的值，OpenCode 本会悄悄改用默认强度（medium），所以流水线会直接报错并列出这个模型的可选值。
5. 自检第二行会显示 `llm: ChatGPT login found ...`。

订阅有用量上限，用完后请求会失败。scan 阶段失败的切片最多审 5 轮，额度到时还没恢复，这些切片就会被丢弃；
其他阶段失败后，等额度恢复按第 5 节「中断后续跑」续跑。并发越高，用得越快。

## 4. 启动和自检

```bash
cd /data/Trace2Fuzz
docker compose --profile local-embedding up -d --no-build --wait
docker compose ps
```

`--no-build` 保证只用已经加载的镜像，不会在服务器上触发构建（服务器上没有嵌入模型的权重目录）。
第一次启动要把 15 GB 权重载入显存，`--wait` 最多等 10 分钟。

然后在运行容器里自检：

```bash
docker compose exec trace2fuzz python3 docker/selfcheck.py
```

正常输出三行：

```text
embedding: dimension 4096 (model qwen3-embedding-8b)
llm endpoint: serves ['<模型名>'] | configured <模型名>
llm via OpenCode: OK | reply: '...' | stop_reason: completed
```

- 第一行检查嵌入服务，用的是流水线自己的调用方式；本地 8B 模型还会校验维度为 4096。
- 第二行检查 `.env` 里的大模型地址能连上，且服务端确实提供了配置的模型名；名字对不上会标 `<- NOT SERVED`。
- 第三行通过 OpenCode 发一次真实请求，走的是各个智能体阶段实际用的路径。
- 前两项失败会直接报错退出；第三行为 `FAILED` 时，对照上一节的要求检查大模型服务的日志。

## 5. 跑 lcms 和 curl

在宿主上执行。流水线在运行容器里后台运行，日志写在挂载的仓库目录里，宿主上直接能看：

```bash
mkdir -p workspace/lcms workspace/curl
docker compose exec -d trace2fuzz bash -c \
  'python3 -m src.cli.pipeline lcms --concurrency 8 --fuzz-concurrency 16 > workspace/lcms/pipeline.log 2>&1'
docker compose exec -d trace2fuzz bash -c \
  'python3 -m src.cli.pipeline curl --concurrency 8 --fuzz-concurrency 16 > workspace/curl/pipeline.log 2>&1'
tail -f workspace/lcms/pipeline.log
```

- 阶段依次是 scan → preprocess → driver_rounds → fuzz_run。最后一阶段会准备 AFL++ 4.33c 和 ASan+UBSan 构建产物，默认运行 10 次、每次 24 小时。日志开头打印 `Run ID`，所有产物在 `workspace/<库>/` 下。若只需生成 driver，使用 `--to driver_rounds`。
- scan 阶段审计失败的切片会自动再审，连第一轮最多 5 轮；仍失败的切片被丢弃（连同错误记在 `stages/scan/unit-audit-findings.json` 里），
  扫描照常完成，进入下一阶段。
- `--concurrency N`：同时发给大模型的请求数（默认 4），按自部署服务的吞吐量定。
- `--fuzz-concurrency M`：driver_rounds 里同时运行的 fuzzer 数（默认等于 CPU 数）。每个 fuzzer 最多用 2.5 GB 内存，M 乘以 2.5 GB 要放得进空闲内存。
  lcms 和 curl 同时跑时两边分摊 CPU 和内存。
- 同一个库同时只能跑一条流水线，不同的库可以并行。
- curl 的扫描和 preprocess 构建会联网下载 7 个依赖（GitHub、gnu.org、openldap.org），服务器要能访问外网，或者设 `T2F_PROXY`。
  最终 fuzz 阶段使用单独的 AFL++ 构建产物；首次安装 AFL++ 可能需要联网。

### 中断后续跑

```bash
docker compose exec -d trace2fuzz bash -c \
  'python3 -m src.cli.pipeline lcms --run-id <run_id> --from <第一个待执行阶段> >> workspace/lcms/pipeline.log 2>&1'
```

- 没跑完的 scan 用同一个 `--run-id` 续跑时，已经审计成功的切片直接复用。
- 必须用 `--from` 选择第一个待执行阶段；程序遇到选中范围内已存在的阶段结果会报错，不会自动跳过。例如 scan 已完成时用 `--from preprocess`。
  如果失败阶段已经写入 `stages/<阶段>/result.json`，先检查诊断并归档该文件，再用 `--run-id <run_id> --from <阶段>` 明确重试。
- 中止容器里所有正在跑的流水线：`docker compose restart trace2fuzz`，之后照上面续跑。
- 每个 run 冻结了创建时的 provider、全局及四个下游阶段模型配置（`config/agent-env.json`）。这些设置变化时要开新 run。
  `UNIT_AUDIT_MODEL`、推理强度和温度目前不在冻结字段中，复现时需另行保持一致。最终 campaign 的恢复规则见根 README 的「续跑与配置快照」。

## 6. 常见问题

- **嵌入容器启动时报 `unsatisfied condition: cuda>=12.9`**：驱动太旧，需要 535 或更新。
- **嵌入容器日志里显存不足、没有 KV 缓存空间**：调大 `EMBEDDING_GPU_UTIL`，或用 `EMBEDDING_GPU` 换一张空闲的卡。
- **自检第二行连不上大模型**：确认服务监听 `0.0.0.0`、地址写到 `/v1` 为止；设了 `T2F_PROXY` 时，大模型地址要在 `T2F_NO_PROXY` 里。
- **大模型返回 400 "maximum context length"**：服务端上下文太小，见第 3 节的要求。
- **scan 报 `is not a clean checkout`**：`test_lib/<库>` 里有不属于检出的文件。只允许 `build_analysis`、`build_sanitize`、`build_coverage`、`.clangd`，
  其他文件移出源码树后再跑。
- **curl 构建时依赖下载失败**：网络问题，用同一个 `--run-id` 重跑即可。

停止所有服务：`docker compose --profile local-embedding down`。运行产物在宿主的 `workspace/` 里，不受影响。
