import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class MountPoint:
    """Represents a single mount point entry."""

    device: bytes = b''
    path: bytes = b''
    mount_type: bytes = b''
    options: list[bytes] = field(default_factory=list)

    def parse(self, raw: bytes):
        """Parses a single line from the mount point dump."""
        raw = raw.strip()
        match = re.match(
            rb'(\S+)\s+on\s+(\S+)\s+type\s+(\S+)\s+\((.*?)\)', raw
        )
        if match:
            self.device = match.group(1)
            self.path = match.group(2)
            self.mount_type = match.group(3)
            self.options = [opt.strip() for opt in match.group(4).split(b',')]


def parse_mount_points(dumpstate_content: RawData) -> list[MountPoint] | None:
    """Parses the 'MOUNT POINT DUMP' section."""
    LOGGER.info("Parsing \"MOUNT POINT DUMP\" section...")

    mount_section_match = re.search(
        rb'------ MOUNT POINT DUMP \(mount\) ------\n(.*?)\n------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not mount_section_match:
        return None

    mount_content = mount_section_match.group(1)
    mount_points: list[MountPoint] = []
    for line in mount_content.strip().split(b'\n'):
        if line.strip():
            mp = MountPoint()
            mp.parse(line)
            mount_points.append(mp)
    return mount_points
