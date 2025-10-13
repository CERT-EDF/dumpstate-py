import re
from dataclasses import dataclass, field
from datetime import datetime

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class AnrInfo:
    """Holds information about a single ANR file."""

    permissions: bytes
    owner: bytes
    group: bytes
    size: int
    timestamp: datetime
    filename: bytes


@dataclass
class AnrFileData:
    """Holds all parsed ANR file entries."""

    files: list[AnrInfo] = field(default_factory=list)
    total_size: int = 0

    def add_file(self, anr_info: AnrInfo):
        self.files.append(anr_info)


def parse_anr_files(dumpstate_content: RawData) -> AnrFileData | None:
    """Parses the 'ANR FILES' section of the bug report."""
    LOGGER.info("Parsing \"ANR FILES\" section...")

    section_match = re.search(
        rb'------ ANR FILES .*?------\n(.*?)\n------ .*?------',
        dumpstate_content.raw,
        re.DOTALL,
    )

    if not section_match:
        return None

    content_block = section_match.group(1).strip()
    lines = content_block.split(b'\n')
    anr_data = AnrFileData()

    # Regex for ls -lt output line
    # e.g., -rw------- 1 system system 45768 2025-04-25 13:41 anr_2025-04-25-13-41-55-543
    anr_pattern = re.compile(
        rb'^(?P<perms>[\w-]+)\s+'
        rb'\d+\s+'
        rb'(?P<owner>\w+)\s+'
        rb'(?P<group>\w+)\s+'
        rb'(?P<size>\d+)\s+'
        rb'(?P<date>\d{4}-\d{2}-\d{2})\s+'
        rb'(?P<time>\d{2}:\d{2})\s+'
        rb'(?P<filename>.*)$'
    )

    for line in lines:
        line = line.strip()
        if line.startswith(b'total'):
            anr_data.total_size = int(line.split()[-1])
            continue

        match = anr_pattern.match(line)
        if match:
            data = match.groupdict()
            timestamp_str = f"{data['date'].decode('utf-8')} {data['time'].decode('utf-8')}"
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M')

            anr_info = AnrInfo(
                permissions=data['perms'],
                owner=data['owner'],
                group=data['group'],
                size=int(data['size']),
                timestamp=timestamp,
                filename=data['filename'],
            )
            anr_data.add_file(anr_info)
    return anr_data
