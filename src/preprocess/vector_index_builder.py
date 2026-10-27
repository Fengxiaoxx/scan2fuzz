"""Build a FAISS index from immutable, ABI-identified API documents."""

import os
import shutil
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document

from src.experiment import RunArtifactStore


def build_vector_index(
    library_name: str,
    artifact_store: RunArtifactStore,
) -> str:
    """Build the vector index using canonical API IDs as document keys."""
    load_dotenv()

    index_dir = Path("info_lib") / library_name / "api" / "faiss_index"
    doc_index = artifact_store.read_json("stages/preprocess/api-doc-index.json")
    if not isinstance(doc_index, dict) or not doc_index:
        raise ValueError("API document index must be a non-empty object")

    documents = []
    for api_id, relative_path in sorted(doc_index.items()):
        doc = artifact_store.read_json(relative_path)
        if not isinstance(doc, dict) or doc.get("api_id") != api_id:
            raise ValueError(f"invalid API document: {relative_path}")
        display_name = str(doc["function_name"])
        qualified_name = str(doc["qualified_name"])
        parts = [
            f"API identity: {api_id}",
            f"Function: {qualified_name}",
        ]
        if doc.get("summary"):
            parts.append(f"Summary: {doc['summary']}")
        documents.append(
            Document(
                page_content="\n".join(parts),
                metadata={
                    "api_id": api_id,
                    "function_name": display_name,
                    "qualified_name": qualified_name,
                },
            )
        )

    # Create embeddings
    embedding_model = os.environ["EMBEDDING_MODEL"]
    batch_size = int(os.getenv("EMBEDDING_BATCH_SIZE", "20"))
    if batch_size < 1:
        raise ValueError("EMBEDDING_BATCH_SIZE must be a positive integer")
    embeddings = OpenAIEmbeddings(
        model=embedding_model,
        openai_api_key=os.environ["EMBEDDING_API_KEY"],
        openai_api_base=os.environ["EMBEDDING_API_BASE"],
        chunk_size=batch_size,
        # Let the embedding service tokenize text with its own vocabulary.
        check_embedding_ctx_length=False,
    )

    # Build FAISS index
    vector_store = FAISS.from_documents(documents, embeddings)

    # Save index
    if index_dir.exists():
        shutil.rmtree(index_dir)
    index_dir.parent.mkdir(parents=True, exist_ok=True)
    vector_store.save_local(str(index_dir))

    logger.info(f"Built vector index: {len(documents)} functions -> {index_dir}")
    return str(index_dir)
