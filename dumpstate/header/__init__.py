import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class DumpstateHeader:
    """Represents the main header of a dumpstate file."""

    timestamp: bytes | None = None
    build: bytes | None = None
    build_fingerprint: bytes | None = None
    bootloader: bytes | None = None
    radio: bytes | None = None
    network: bytes | None = None
    sdk_version: int = 0
    sdk_extensions = {}
    kernel: bytes | None = None
    command_line: bytes | None = None
    uptime: dict[str, bytes | dict[str, float]] = field(default_factory=dict)


def parse_dumpstate_header(
    dumpstate_content: RawData,
) -> DumpstateHeader | None:
    """Parses the main header of a dumpstate file."""
    LOGGER.info("Parsing \"HEADER\" section...")

    header_match = re.search(
        rb'== dumpstate: (.*?)\n========================================================\n\n(.*?)(?=\n------\s|\Z)',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not header_match:
        return None

    header = DumpstateHeader()
    header.timestamp = header_match.group(1).strip()
    header_content = header_match.group(2)

    # Use a buffer to handle multi-line values like 'Kernel' and 'Command line'
    lines = header_content.split(b'\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        if b':' in line:
            key, value = line.split(b':', 1)
            key = key.strip().lower().replace(b' ', b'_').replace(b'-', b'_')
            value = value.strip()

            # Look ahead for multi-line values
            i += 1
            while i < len(lines) and b':' not in lines[i]:
                value += b'\n' + lines[i].strip()
                i += 1
            i -= 1  # Go back one line to not skip the next key-value pair

            if hasattr(header, key.decode("utf-8")):
                if key == b'sdk_version':
                    header.sdk_version = int(value)
                elif key == b'sdk_extensions':
                    exts = re.findall(rb'(\w+)=(\d+)', value)
                    header.sdk_extensions = {k: int(v) for k, v in exts}
                elif key == b'uptime':
                    load_avg_match = re.search(
                        rb'load average: ([\d\.]+), ([\d\.]+), ([\d\.]+)',
                        value,
                    )
                    if load_avg_match:
                        header.uptime['load_average'] = {
                            '1m': float(load_avg_match.group(1)),
                            '5m': float(load_avg_match.group(2)),
                            '15m': float(load_avg_match.group(3)),
                        }
                    uptime_str_match = re.search(
                        rb'up (.*?),?\s+load average:', value
                    )
                    if uptime_str_match:
                        duration_str = uptime_str_match.group(1).strip()
                        header.uptime['raw_duration'] = duration_str
                        duration_parts = {}
                        matches = re.findall(
                            rb'(\d+)\s+(week|day|hour|minute)s?', duration_str
                        )
                        for val, unit in matches:
                            unit_plural = (
                                unit + b's'
                                if not unit.endswith(b's')
                                else unit
                            )
                            duration_parts[unit_plural] = int(val)
                        header.uptime['duration'] = duration_parts
                else:
                    setattr(header, key.decode("utf-8"), value)
        i += 1

    return header
