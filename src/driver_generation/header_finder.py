"""
Header Finder - Find the header to #include for an API.

Source: the run-scoped api_declarations.csv produced from the frozen installed
public interface. Lookup is by canonical API id, never by display name.
"""

import csv
from pathlib import Path
from typing import Dict
from loguru import logger

from src.core import get_project_root
from src.experiment import RunArtifactStore


class HeaderFinder:
    """Find header files for functions from CSV"""

    def __init__(self, library_name: str):
        self.library_name = library_name
        store = RunArtifactStore.from_environment(get_project_root(), library_name)
        self.csv_path = store.safe_path(
            "stages/preprocess/structural/api_declarations.csv"
        )
        self.api_to_header: Dict[str, str] = {}
        self._load_csv()

    def _load_csv(self):
        """Load CSV and build function name to header file mapping"""
        try:
            with Path(self.csv_path).open('r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    api_id = row.get('api_id', '').strip()
                    header_file = row.get('header_file', '').strip()
                    if api_id and header_file:
                        if api_id in self.api_to_header:
                            raise ValueError(f"duplicate API declaration: {api_id}")
                        self.api_to_header[api_id] = header_file
            # Loaded CSV silently
        except Exception as e:
            logger.error(f"Failed to load CSV from {self.csv_path}: {e}")
            raise

    def get_include(self, api_id: str) -> str:
        """Get #include statement for the function"""
        header_file = self.api_to_header.get(api_id, "")
        if not header_file:
            return ""
        return f"#include <{header_file}>"
