"""
Knowledge access layer: FAISS-backed vector search over per-API docs.
"""

from src.knowledge.vector_search import VectorSearchTool

__all__ = [
    "VectorSearchTool",
]
