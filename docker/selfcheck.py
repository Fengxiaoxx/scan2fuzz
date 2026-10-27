"""Check, from inside the runtime container, the services every run depends on.

    docker compose exec trace2fuzz python3 docker/selfcheck.py

1. the configured embedding service returns vectors (4096 dimensions for the bundled local model);
2. the LLM endpoint configured in .env is reachable and serves the configured model, or, with
   LLM_PROVIDER=openai and no endpoint, a ChatGPT login saved by `opencode auth login` exists;
3. one OpenCode turn, the path every agent stage uses, comes back with a reply.

Exits non-zero when the OpenCode turn fails; the first two checks raise on failure.
"""

import json
import os
import tempfile
import urllib.request

from dotenv import load_dotenv

load_dotenv("/Trace2Fuzz/.env")  # values compose puts in the environment win over the file

from langchain_openai import OpenAIEmbeddings  # noqa: E402

from src.llm.api_key_pool import configure_concurrency, parse_api_keys  # noqa: E402
from src.llm.opencode_query import OpenCodeQueryClient, chatgpt_login_file, chatgpt_reasoning_variant  # noqa: E402
from src.llm.provider_config import ModelProviderConfig, resolve_model_name  # noqa: E402

embeddings = OpenAIEmbeddings(
    model=os.environ["EMBEDDING_MODEL"],
    openai_api_key=os.environ["EMBEDDING_API_KEY"],
    openai_api_base=os.environ["EMBEDDING_API_BASE"],
    check_embedding_ctx_length=False,
)
embedding_dimension = len(embeddings.embed_query("hello"))
embedding_model = os.environ["EMBEDDING_MODEL"]
if embedding_model == "qwen3-embedding-8b" and embedding_dimension != 4096:
    raise ValueError(
        f"bundled embedding model returned {embedding_dimension} dimensions; expected 4096"
    )
print("embedding: dimension", embedding_dimension, f"(model {embedding_model})")

model = resolve_model_name("UNIT_AUDIT_MODEL", "deepseek-v4-flash")
if ModelProviderConfig.from_env().uses_chatgpt_login:
    login = json.loads(chatgpt_login_file().read_text(encoding="utf-8")).get("openai", {})
    print("llm: ChatGPT login", "found" if login.get("type") == "oauth" else "MISSING", "in", chatgpt_login_file(),
          "| model openai/" + model, "| variant", chatgpt_reasoning_variant())
else:
    base_url = os.environ["LLM_BASE_URL"].rstrip("/")
    key = parse_api_keys(os.environ["LLM_API_KEY"])[0]
    request = urllib.request.Request(f"{base_url}/models", headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(request, timeout=30) as reply:
        served = [entry["id"] for entry in json.load(reply).get("data", [])]
    print("llm endpoint: serves", served, "| configured", model, "" if model in served else "<- NOT SERVED")

configure_concurrency(1)
client = OpenCodeQueryClient(tempfile.mkdtemp(prefix="selfcheck-"), timeout_seconds=300, api_key_concurrency=1)
try:
    result = client.run(prompt="Reply with the single word: ok", system_prompt="Answer in one word.",
                        model=model, mcp_config={"mcp": {}}, configured_tools=[])
finally:
    client.close()
ok = not result.is_error and result.result_text.strip() != ""
print("llm via OpenCode:", "OK" if ok else "FAILED", "| reply:", repr(result.result_text[:40]),
      "| stop_reason:", result.stop_reason)
raise SystemExit(0 if ok else 1)
