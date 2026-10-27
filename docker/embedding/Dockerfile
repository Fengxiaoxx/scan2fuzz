# Qwen3-Embedding-8B with its weights baked in, served as an OpenAI-compatible /v1/embeddings
# endpoint. The weights come from the build context named "weights" (a downloaded copy of
# Qwen/Qwen3-Embedding-8B), so the running container needs no network.
ARG VLLM_IMAGE=vllm/vllm-openai:v0.31.0-cu129
FROM ${VLLM_IMAGE}

COPY --from=weights . /models/Qwen3-Embedding-8B

# The cu129 image pairs a CUDA 12.9 torch with a torchcodec built for CUDA 13 (it needs
# libnvrtc.so.13), and that OSError at import keeps `vllm serve` from starting at all. vLLM treats
# torchcodec as optional (audio/video decoding only), so text embeddings run without it.
RUN python3 -m pip uninstall -y torchcodec

ENV HF_HUB_OFFLINE=1
ENTRYPOINT ["vllm", "serve", "/models/Qwen3-Embedding-8B", "--runner=pooling"]
