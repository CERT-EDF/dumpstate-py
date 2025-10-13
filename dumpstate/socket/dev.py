import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class NetworkDevInfoData:
    name: bytes
    receive_bytes: int
    receive_packets: int
    transmit_bytes: int
    transmit_packets: int


def parse_network_dev_info(
    dumpstate_content: RawData,
) -> list[NetworkDevInfoData] | None:
    """
    Parses the 'NETWORK DEV INFO' section of the bug report.
    """
    LOGGER.info("Parsing \"NETWORK DEV INFO\" section...")

    section_match = re.search(
        rb'------ NETWORK DEV INFO .*?------\n(.*?)\n------ .*?------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not section_match:
        return None

    section_content = section_match.group(1)
    dev_info: list[NetworkDevInfoData] = []

    for line in section_content.strip().split(b'\n'):
        line = line.strip()
        if not line:
            continue

        if not line.startswith(b'Inter-') and not line.startswith(b'face '):
            match = re.match(rb'^\s*([a-zA-Z0-9_]+):\s+((?:\d+\s*)+)', line)
            if match:
                interface_name = match.group(1)
                stats = [int(n) for n in match.group(2).strip().split()]
                dev_info.append(
                    NetworkDevInfoData(
                        interface_name, stats[0], stats[1], stats[8], stats[9]
                    )
                )

    return dev_info
