"""Provider-neutral configuration for Trace2Fuzz model-backed agents.

The rest of the pipeline only chooses a model and submits an agent request. This
module owns the mapping from environment variables to the provider configuration
understood by the OpenCode runtime. API-key values never enter generated metadata;
Credentials are read separately from ``LLM_API_KEY`` by the runtime.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Mapping, Optional
from urllib.parse import urlsplit

from src.llm.api_key_pool import parse_api_keys


DEFAULT_PROVIDER_ID = "openai"
DEFAULT_CUSTOM_PROVIDER_ID = "trace2fuzz_custom"
GLOBAL_MODEL_ENV = "LLM_MODEL"
PROVIDER_ID_ENV = "LLM_PROVIDER"
BASE_URL_ENV = "LLM_BASE_URL"
API_KEY_ENV = "LLM_API_KEY"

PROVIDER_ENV_KEYS = (
    GLOBAL_MODEL_ENV,
    PROVIDER_ID_ENV,
    BASE_URL_ENV,
)

_RESERVED_PROVIDER_IDS = {"openai", "ollama", "lmstudio"}
_PROVIDER_ID_RE = re.compile(r"[A-Za-z0-9_-]+", re.ASCII)
# OpenCode's built-in OpenAI provider, signed in with a ChatGPT plan by `opencode auth login`.
CHATGPT_LOGIN_PROVIDER_ID = "openai"


def _value(environ: Mapping[str, str], key: str) -> str:
    value = environ.get(key, "")
    return value.strip() if isinstance(value, str) else ""


@dataclass(frozen=True)
class ModelProviderConfig:
    """Validated model-provider settings without credential material."""

    provider_id: str = DEFAULT_PROVIDER_ID
    base_url: str = ""
    api_key_env: str = ""

    @classmethod
    def from_env(
        cls,
        environ: Optional[Mapping[str, str]] = None,
        *,
        require_api_key: bool = True,
    ) -> "ModelProviderConfig":
        env = os.environ if environ is None else environ
        base_url = _value(env, BASE_URL_ENV).rstrip("/")
        explicit_provider = _value(env, PROVIDER_ID_ENV)
        if not explicit_provider and not base_url:
            # The ChatGPT login is chosen explicitly, never as the fallback of a missing configuration.
            raise ValueError(
                f"no model provider configured: set {BASE_URL_ENV} and {API_KEY_ENV}, or "
                f"{PROVIDER_ID_ENV}={CHATGPT_LOGIN_PROVIDER_ID} for the ChatGPT login of OpenCode"
            )
        provider_id = explicit_provider or DEFAULT_CUSTOM_PROVIDER_ID
        config = cls(
            provider_id=provider_id,
            base_url=base_url,
            api_key_env=API_KEY_ENV if _value(env, API_KEY_ENV) else "",
        )
        config.validate(env, require_api_key=require_api_key)
        return config

    @property
    def is_custom(self) -> bool:
        return self.provider_id not in _RESERVED_PROVIDER_IDS

    @property
    def uses_chatgpt_login(self) -> bool:
        """No endpoint or key of our own: OpenCode's OpenAI provider with its ChatGPT login."""
        return self.provider_id == CHATGPT_LOGIN_PROVIDER_ID and not self.base_url

    def validate(
        self,
        environ: Optional[Mapping[str, str]] = None,
        *,
        require_api_key: bool = True,
    ) -> None:
        env = os.environ if environ is None else environ
        if not _PROVIDER_ID_RE.fullmatch(self.provider_id):
            raise ValueError(
                f"{PROVIDER_ID_ENV} must match [A-Za-z0-9_-]+"
            )

        if self.uses_chatgpt_login:
            if _value(env, API_KEY_ENV):
                raise ValueError(
                    f"{PROVIDER_ID_ENV}={CHATGPT_LOGIN_PROVIDER_ID} without {BASE_URL_ENV} uses the "
                    f"ChatGPT login saved by `opencode auth login`; leave {API_KEY_ENV} unset"
                )
            return

        if self.is_custom:
            if not self.base_url:
                raise ValueError(
                    f"{BASE_URL_ENV} is required for custom provider "
                    f"{self.provider_id!r}"
                )
            parsed = urlsplit(self.base_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(
                    f"{BASE_URL_ENV} must be an absolute http(s) URL"
                )
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError(
                    f"{BASE_URL_ENV} must not contain credentials, a query, or a fragment"
                )
        elif self.base_url:
            raise ValueError(
                f"provider id {self.provider_id!r} is reserved; set "
                f"{PROVIDER_ID_ENV} to a custom id when using {BASE_URL_ENV}"
            )

        if require_api_key and not _value(env, API_KEY_ENV):
            raise ValueError(f"{API_KEY_ENV} is required")
        if _value(env, API_KEY_ENV):
            parse_api_keys(_value(env, API_KEY_ENV))

    def frozen_environment(self) -> dict[str, str]:
        """Return reproducibility fields suitable for ``agent-env.json``."""
        return {
            PROVIDER_ID_ENV: self.provider_id,
            BASE_URL_ENV: self.base_url,
        }


def resolve_model_name(
    stage_environment_key: str,
    default: str,
    environ: Optional[Mapping[str, str]] = None,
) -> str:
    """Resolve per-stage override, then global model, then code default."""
    env = os.environ if environ is None else environ
    return (
        _value(env, stage_environment_key)
        or _value(env, GLOBAL_MODEL_ENV)
        or default
    )
