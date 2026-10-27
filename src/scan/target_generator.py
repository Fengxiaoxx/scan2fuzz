"""
Target generator - generates targets.txt from scan results
"""

import os
import tempfile
from collections import Counter
from itertools import chain
from pathlib import PurePosixPath
from typing import List, Optional

from loguru import logger

from src.core import Target


class TargetGenerator:
    """Generates targets.txt from scan results"""

    # Exclude patterns: targets matching these patterns will be filtered out
    EXCLUDE_PATH_PATTERNS = [
        'third_party',      # Third-party library code
        # 'test',           # Test code (uncomment if needed)
        # 'example',        # Example code (uncomment if needed)
        # '/build/',        # Build-generated files (uncomment if needed)
    ]

    def __init__(self, targets_file: str, test_lib_dir: str):
        self.targets_file = targets_file
        self.test_lib_dir = test_lib_dir

    def normalize_targets(self, *target_groups: List[Target]) -> None:
        """Normalize target paths in place to be relative to the library root."""
        for targets in target_groups:
            for target in targets:
                target.file_path = self._normalize_path(target.file_path)

    def _normalize_path(self, file_path: str) -> str:
        """Normalize path to relative to library root"""
        if os.path.isabs(file_path):
            try:
                file_path = os.path.relpath(file_path, '.')
            except ValueError:
                pass  # Different disk, keep absolute path

        # Remove ./ prefix if present
        if file_path.startswith('./'):
            file_path = file_path[2:]

        # Remove test_lib_dir prefix to get library-relative path
        if self.test_lib_dir:
            lib_prefix = self.test_lib_dir
            if lib_prefix.startswith('./'):
                lib_prefix = lib_prefix[2:]
            if lib_prefix.endswith('/'):
                lib_prefix = lib_prefix[:-1]

            # Remove prefix and leading slash
            if file_path.startswith(lib_prefix + '/'):
                file_path = file_path[len(lib_prefix) + 1:]
            elif file_path.startswith(lib_prefix):
                file_path = file_path[len(lib_prefix):]

        return file_path

    @classmethod
    def _exclusion_reason(cls, file_path: str) -> Optional[str]:
        """Return why a normalized target path is outside the fuzzing scope."""
        parts = PurePosixPath(file_path.replace('\\', '/')).parts
        if (
            len(parts) >= 3
            and parts[0] == 'build_analysis'
            and parts[1].endswith('-install')
        ):
            return 'dependency install directory'

        for pattern in cls.EXCLUDE_PATH_PATTERNS:
            if pattern in file_path:
                return f"path pattern {pattern!r}"

        return None

    def generate(
        self,
        infer_targets: List[Target],
        codeql_targets: Optional[List[Target]] = None,
    ) -> bool:
        """Generate targets.txt file"""
        if codeql_targets is None:
            codeql_targets = []

        return self.generate_groups({"Infer": infer_targets, "CodeQL": codeql_targets})

    def generate_groups(self, target_groups: dict[str, List[Target]]) -> bool:
        """Merge named groups in order; the first severity at a location wins."""
        self.normalize_targets(*target_groups.values())

        # Merge and deduplicate (based on file path and line number)
        all_targets = {}  # key: (file_path, line_no), value: Target
        excluded_reasons = Counter()

        for target in chain.from_iterable(target_groups.values()):
            reason = self._exclusion_reason(target.file_path)
            if reason is not None:
                excluded_reasons[reason] += 1
                continue

            key = (target.file_path, target.line_no)

            if key not in all_targets:
                all_targets[key] = target
            else:
                # If multiple issues at same location, merge descriptions
                existing = all_targets[key]
                if target.description not in existing.description:
                    all_targets[key].description += f" | {target.description}"

        if excluded_reasons:
            summary = ', '.join(
                f'{reason}={count}'
                for reason, count in sorted(excluded_reasons.items())
            )
            logger.info(
                f'Excluded {sum(excluded_reasons.values())} out-of-scope '
                f'targets: {summary}'
            )

        # Sort by file path, then by line number
        sorted_targets = sorted(
            all_targets.values(),
            key=lambda t: (t.file_path, t.line_no)
        )

        # Replace the destination only after the complete new file is durable.
        temporary_path = None
        try:
            target_dir = os.path.dirname(os.path.abspath(self.targets_file))
            with tempfile.NamedTemporaryFile(
                mode='w',
                encoding='utf-8',
                dir=target_dir,
                prefix='.targets.',
                delete=False,
            ) as temporary_file:
                temporary_path = temporary_file.name
                for target in sorted_targets:
                    temporary_file.write(target.to_string() + '\n')
                temporary_file.flush()
                os.fsync(temporary_file.fileno())

            os.replace(temporary_path, self.targets_file)
            temporary_path = None

            counts = ", ".join(
                f"{name}: {len(targets)}" for name, targets in target_groups.items()
            )
            logger.success(
                f"Generated {self.targets_file}: {len(sorted_targets)} targets ({counts})"
            )
            return True

        except Exception as e:
            if temporary_path and os.path.exists(temporary_path):
                try:
                    os.remove(temporary_path)
                except OSError as cleanup_error:
                    logger.warning(
                        f"Failed to remove temporary targets file: {cleanup_error}"
                    )
            logger.error(f"Failed to write targets.txt: {e}")
            return False
