import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class BatteryStats:
    """Represents the CHECKIN BATTERYSTATS section."""

    version_info: dict = field(default_factory=dict)
    data: dict[bytes, list[dict[str, bytes | list[bytes]]]] = field(
        default_factory=dict
    )


def parse_battery_stats(dumpstate_content: RawData):
    """Parses the 'CHECKIN BATTERYSTATS' section."""
    LOGGER.info("Parsing \"CHECKIN BATTERYSTATS\" section...")

    battery_section_match = re.search(
        rb'------ CHECKIN BATTERYSTATS \(.*?\) ------\n(.*?)\n------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not battery_section_match:
        return None

    battery_content = battery_section_match.group(1)
    stats = BatteryStats()

    for line in battery_content.strip().split(b'\n'):
        parts = [p.strip(b'"') for p in line.strip().split(b',')]
        if len(parts) < 4:
            continue

        uid_or_zero, category_letter, subcategory = (
            parts[1],
            parts[2],
            parts[3],
        )
        data = parts[4:]

        if subcategory not in stats.data:
            stats.data[subcategory] = []

        entry: dict[str, bytes | list[bytes]] = {
            'uid_or_zero': uid_or_zero,
            'category_letter': category_letter,
            'data': data,
            'raw': line.strip(),
        }
        stats.data[subcategory].append(entry)

    return stats
