"""
Semantic Search Tool - Search library functions by description for LLM agents
"""

from src.knowledge import VectorSearchTool


class SemanticFunctionSearcher:
    """Reusable semantic search helper shared by agent tool wrappers."""

    def __init__(self, library_name: str):
        self.library_name = library_name
        self.search_tool = VectorSearchTool(library_name)
        self.search_tool.load()

    def search(self, query: str) -> str:
        """Search library functions by functionality description."""
        return self.search_tool.search_with_docs(query, k=3)
