"""
Driver Context Builder - Build context for driver code generation
"""

import os
from typing import Dict, List

from loguru import logger
from src.core import normalize_language
from src.driver_generation.header_finder import HeaderFinder


class DriverContextBuilder:
    """Build context (headers, sequence info, etc.) for driver code generation by Agent"""

    def __init__(self, library_name: str, language: str = "C"):
        self.library_name = library_name
        self.language = normalize_language(language)
        self.target_api_id: str = ""
        self.target_api: str = ""
        self.api_doc: Dict = {}
        self.targets: List[Dict] = []
        self.header_finder = HeaderFinder(library_name)

    def load_target(
        self,
        api_id: str,
        target_api: str,
        api_doc: Dict,
        targets: List[Dict],
    ):
        """
        Load the target-API-centric context the agent will reason from.

        Args:
            target_api: name of the entry API the driver is built around
            api_doc:    the API's documentation dict (signature/summary/source/...)
            targets:    list of {target_key, file, line, severity, description,
                        chain} entries - one per target line this API can reach.
                        Generation receives the target location, but not the
                        finding description or static call chain. Full metadata
                        remains available to later repair and refinement stages.
        """
        self.target_api_id = api_id
        self.target_api = target_api
        self.api_doc = api_doc or {}
        self.targets = targets or []

    def get_headers(self) -> str:
        """Build the include block, with extern C wrapping for C libraries.

        Only the target API's header is injected as a starting point; the agent
        discovers and adds any further setup/teardown API headers itself via the
        API fact base and source lookup tools. For single-header libraries this
        already covers everything.
        """
        # Standard C headers (C++-compatible, no wrapping needed)
        standard_headers = [
            "#include <stddef.h>",
            "#include <stdio.h>",
            "#include <stdint.h>",
            "#include <stdlib.h>",
            "#include <string.h>"
        ]

        # Library-specific header for the target API (extern C wrapped for C libs)
        library_headers = set()
        if self.target_api_id:
            include = self.header_finder.get_include(self.target_api_id)
            if include:
                library_headers.add(include)
            else:
                logger.warning(f"No header found for {self.target_api}")

        # Build header section
        result = []
        result.extend(sorted(standard_headers))

        if library_headers:
            sorted_lib_headers = sorted(library_headers)
            if self.language == 'C':
                # Wrap C library headers with extern "C"
                result.append('\nextern "C" {')
                result.extend(["    " + h for h in sorted_lib_headers])
                result.append("}")
            else:
                # C++ library headers, no wrapping
                result.extend(sorted_lib_headers)

        return "\n".join(result)

    def api_doc_fields(self) -> Dict[str, str]:
        """Raw API-doc values for the prompt placeholders; the fixed text lives in prompt.py."""
        doc = self.api_doc
        api_def = next((t.get('api_def') for t in self.targets if t.get('api_def')), None)
        if api_def and api_def.get('file'):
            defined_in = f"{api_def['file']}:{api_def['line']}:{api_def['col']}"
        else:
            defined_in = str(doc.get('file_path') or "unknown")
        return {
            "target_api": self.target_api,
            "signature": str(doc.get('signature') or "unknown"),
            "defined_in": defined_in,
            "api_source": str(doc.get('source') or ""),
        }

    def target_lines(self) -> str:
        """One line per target line; the section heading lives in prompt.py."""
        lines: List[str] = []
        for t in self.targets:
            ident = t.get('marker') or t.get('target_key', 'unknown')
            sev = t.get('severity', '') or 'UNKNOWN'
            file_path = t.get('file', '')
            line_no = t.get('line', '')
            if file_path and line_no != '':
                lines.append(f"- Target {ident} ({sev}) at {file_path}:{line_no}")
            elif sev:
                lines.append(f"- Target {ident} ({sev})")
            else:
                lines.append(f"- Target {ident}")
        return "\n".join(lines)

    def target_context(self) -> str:
        """Render downstream location and structural path without finding prose."""
        blocks: List[str] = []
        for target in self.targets:
            ident = target.get("marker") or target.get("target_key", "unknown")
            file_path = target.get("file", "")
            line_no = target.get("line", "")
            location = (
                f"{file_path}:{line_no}"
                if file_path and line_no != ""
                else "unknown"
            )
            lines = [f"Target {ident}: {location}"]
            chain = target.get("chain") or []
            if chain:
                lines.append("Candidate static call chain:")
                for index, step in enumerate(chain, start=1):
                    name = step.get("fn") or step.get("symbol") or "unknown"
                    step_file = step.get("file", "")
                    step_line = step.get("line", "")
                    step_location = (
                        f" at {step_file}:{step_line}"
                        if step_file and step_line != ""
                        else ""
                    )
                    lines.append(f"  {index}. {name}{step_location}")
            else:
                lines.append("Candidate static call chain: unavailable")
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks)

    @staticmethod
    def _include_description() -> bool:
        """Reported findings render unless T2F_PROMPT_DESCRIPTION disables them."""
        value = os.environ.get("T2F_PROMPT_DESCRIPTION", "").strip().lower()
        return value not in ("0", "off", "false", "no")

    def reported_finding(self) -> str:
        """The auditor's reported finding; empty when the render policy disables it."""
        if not self._include_description():
            return ""
        for t in self.targets:
            desc = (t.get('description') or '').strip()
            if desc:
                return desc
        return ""

    def format_target_info(self) -> str:
        """Composed block for the repair/refiner prompts (labels mirror prompt.py)."""
        fields = self.api_doc_fields()
        parts = [
            f"Target API: {fields['target_api']}",
            f"Signature: {fields['signature']}",
        ]
        if fields['defined_in']:
            parts.append(f"Defined in: {fields['defined_in']}")
        if fields['api_source']:
            parts.append("Source Code:")
            parts.append(fields['api_source'])
        navigation = self.target_context()
        if navigation:
            parts.append("Target navigation and candidate static call chain:")
            parts.append(navigation)
        desc = self.reported_finding()
        if desc:
            parts.append("Reported finding:")
            parts.append(desc)
        return "\n\n".join(parts)
