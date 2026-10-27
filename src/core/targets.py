"""
Target data structure and parser
"""

from dataclasses import dataclass
from typing import List, Optional
from loguru import logger


@dataclass
class Target:
    """Represents a scan target (security issue)"""
    file_path: str
    line_no: int
    severity: str
    description: str
    def to_string(self) -> str:
        """Convert to targets.txt format"""
        # Clean description: remove extra whitespace, merge multiline into single line
        clean_desc = ' '.join(self.description.split())
        return f"{self.file_path}:{self.line_no}: {self.severity}: {clean_desc}"

    def __hash__(self):
        return hash((self.file_path, self.line_no))

    def __eq__(self, other):
        return (self.file_path, self.line_no) == (other.file_path, other.line_no)


class TargetParser:
    """Parse targets.txt file into Target objects"""

    @classmethod
    def parse_file(cls, targets_file: str) -> List[Target]:
        """Parse targets.txt file into Target objects"""
        targets = []

        try:
            with open(targets_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    target = cls.parse_line(line)
                    if target:
                        targets.append(target)
                    else:
                        logger.warning(f"Failed to parse line {line_num}: {line[:50]}...")

            logger.info(f"Parsed {len(targets)} targets from {targets_file}")
            return targets

        except FileNotFoundError:
            logger.error(f"Targets file not found: {targets_file}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse targets file: {e}")
            return []

    @classmethod
    def parse_line(cls, line: str) -> Optional[Target]:
        """Parse single line: path/file.c:123: SEVERITY: description"""
        # Split by ':' - at least 4 parts expected
        parts = line.split(':', 3)

        if len(parts) < 4:
            return None

        try:
            file_path = parts[0].strip()
            line_no = int(parts[1].strip())
            severity = parts[2].strip()
            description = parts[3].strip()

            return Target(
                file_path=file_path,
                line_no=line_no,
                severity=severity,
                description=description
            )
        except (ValueError, IndexError):
            return None
