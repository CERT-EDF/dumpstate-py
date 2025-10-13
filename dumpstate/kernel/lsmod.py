import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class LoadedModule:
    """Represents a single loaded kernel module."""

    name: bytes = b''
    size: int = 0
    used_by: list[bytes] = field(default_factory=list)

    def parse(self, raw: bytes):
        """Parses a line from the 'lsmod' command output."""
        if not raw:
            return
        raw = raw.strip()

        parts = raw.split()
        if len(parts) < 3:
            return
        self.name = parts[0]
        self.size = int(parts[1])
        if len(parts) > 3:
            self.used_by = [module.strip(b',') for module in parts[3:]]


def parse_lsmod(lines: RawData):
    LOGGER.info("Parsing \"LSMOD\" section...")

    lsmod_section_match = re.search(
        rb'------ LSMOD \(lsmod\) ------\n(.*?)\n------', lines.raw, re.DOTALL
    )
    if not lsmod_section_match:
        return None

    lsmod_content = lsmod_section_match.group(1)
    lsmod_modules: list[LoadedModule] = []
    for line in lsmod_content.strip().split(b'\n'):
        if line.strip():
            if not line.startswith(b'Module'):
                lm = LoadedModule()
                lm.parse(line)
                lsmod_modules.append(lm)
    return lsmod_modules
