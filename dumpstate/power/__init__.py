import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class PowerEvent:
    """Represents a single power event (shutdown or reboot)."""

    timestamp: bytes | None = None
    reason: bytes | None = None
    stack_trace: list[bytes] = field(default_factory=list)
    log: list[bytes] = field(default_factory=list)
    boot_info: bytes | None = None


def parse_power_off_reset_reason(
    dumpstate_content: RawData,
) -> list[PowerEvent] | None:
    """Parses the POWER OFF RESET REASON section."""
    LOGGER.info("Parsing \"POWER OFF RESET REASON\" section...")

    power_off_section_match = re.search(
        rb'------ POWER OFF RESET REASON \(.*?\) ------\n(.*?)\n------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not power_off_section_match:
        return None

    events: list[PowerEvent] = []
    content = power_off_section_match.group(1)

    # Split by the date format that starts each new event
    event_blocks = re.split(
        rb'\n(?=\d{2}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2})', content
    )

    for block in event_blocks:
        if not block.strip():
            continue

        event = PowerEvent()
        lines = block.strip().split(b'\n')

        event.timestamp = lines[0]
        in_stack_trace = False

        for line in lines[1:]:
            if line.startswith(b'reason :'):
                event.reason = line.split(b':', 1)[1].strip()
            elif b'java.lang.Exception' in line:
                in_stack_trace = True
                event.stack_trace.append(line)
            elif in_stack_trace and line.startswith(b'\tat '):
                event.stack_trace.append(line)
            elif (
                re.match(rb'\d{4}-\d{2}-\d{2}', line)
                and b'|    ON    |' in line
            ):
                event.boot_info = line.strip()
                in_stack_trace = False
            else:
                in_stack_trace = False
                event.log.append(line.strip())

        events.append(event)

    return events
