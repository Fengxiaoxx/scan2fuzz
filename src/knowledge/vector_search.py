"""
Vector search tool using FAISS
"""

import os
import json
from typing import Dict
from dotenv import load_dotenv
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import FAISS

from src.core import get_project_root
from src.experiment import RunArtifactStore


class VectorSearchTool:
    """FAISS vector search for functions"""

    def __init__(self, library_name: str):
        load_dotenv()
        self.library_name = library_name
        self.run_store = RunArtifactStore.from_environment(
            get_project_root(), library_name
        )
        self.index_dir = self.run_store.safe_path(
            "stages/preprocess/faiss-index"
        )
        self.doc_index = self.run_store.read_json(
            "stages/preprocess/api-doc-index.json"
        )
        if not isinstance(self.doc_index, dict):
            raise ValueError("API document index must be a JSON object")

        embedding_model = os.environ["EMBEDDING_MODEL"]
        self.embeddings = OpenAIEmbeddings(
            model=embedding_model,
            openai_api_key=os.environ["EMBEDDING_API_KEY"],
            openai_api_base=os.environ["EMBEDDING_API_BASE"],
            # Let the embedding service tokenize text with its own vocabulary.
            check_embedding_ctx_length=False,
        )
        self.vector_store = None

    def load(self):
        """Load FAISS index"""
        for name in ("index.faiss", "index.pkl"):
            path = self.index_dir / name
            if not path.is_file():
                raise FileNotFoundError(f"Vector index artifact not found: {path}")

        self.vector_store = FAISS.load_local(
            str(self.index_dir),
            self.embeddings,
            allow_dangerous_deserialization=True
        )

    def search_with_docs(self, query: str, k: int = 3) -> str:
        """
        Search by semantic similarity and return formatted candidate functions with full doc info

        Args:
            query: Search query string
            k: Number of candidates to return

        Returns:
            Formatted string with candidate functions and their full documentation
        """
        if not self.vector_store:
            raise RuntimeError("Vector index is not loaded")

        # Get semantic search results
        results = self.vector_store.similarity_search_with_score(query, k=k)

        if not results:
            return "No results found."

        # Format results with full doc information
        output = f"Found {len(results)} candidates:\n\n"

        for i, (doc, score) in enumerate(results, 1):
            api_id = doc.metadata.get("api_id", "")
            if not api_id:
                raise ValueError("Vector index entry has no api_id")

            doc_info = self._load_api_document(api_id)
            func_name = doc_info["qualified_name"]

            # Format with full doc information
            output += f"{i}. {func_name}\n"
            # Signature intentionally omitted per requirement
            output += f"   Summary: {doc_info.get('summary', 'No summary')}\n"

            # Header file
            header_file = doc_info.get('header_file', '')
            if header_file:
                output += f"   Header File: {header_file}\n"

            # File path
            file_path = doc_info.get('file_path', '')
            if file_path:
                output += f"   File Path: {file_path}\n"

            # Documentation
            comment = doc_info.get('comment', '')
            if comment:
                output += f"   Documentation:\n"
                # Indent the comment content
                comment_lines = comment.split('\n')
                for line in comment_lines:
                    output += f"     {line}\n"

            # Source code
            source = doc_info.get('source', '')
            if source:
                output += f"   Source Code:\n"
                # Indent the source code
                source_lines = source.split('\n')
                for line in source_lines:
                    output += f"     {line}\n"

            output += "\n"

        return output.strip()

    def _load_api_document(self, api_id: str) -> Dict:
        """Load full documentation for one canonical public API."""
        try:
            relative = self.doc_index[api_id]
            doc_file = self.run_store.safe_path(relative)
            with open(doc_file, 'r', encoding='utf-8') as f:
                value = json.load(f)
            if not isinstance(value, dict) or value.get("api_id") != api_id:
                raise ValueError("API document identity mismatch")
            return value
        except (KeyError, OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Failed to load API document for {api_id}: {exc}"
            ) from exc
