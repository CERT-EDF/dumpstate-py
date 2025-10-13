import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class KeyguardServiceInfo:
    """Represents the KeyguardService information."""

    service_hash: bytes = b''
    pid: int = 0
    user: int = 0
    unlock_info_log: list[dict[str, bytes]] = field(default_factory=list)
    user_settings: dict[int, dict[bytes, bytes]] = field(default_factory=dict)


def parse_keyguard_service(dumpstate_content: RawData):
    """Parses the KeyguardService section."""
    LOGGER.info("Parsing \"KeyguardService\" section...")

    section_lines = []
    current_section = None

    for line in dumpstate_content.lines:
        if line.startswith(
            b'SERVICE com.android.systemui/.keyguard.KeyguardService'
        ):
            current_section = 'keyguard'
            section_lines = [line]  # Start with the header
        elif line.startswith(b'------ ') and b'was the duration of' in line:
            current_section = None
        elif current_section:
            section_lines.append(line)

    if not section_lines:
        return None

    header_match = re.search(
        rb'SERVICE\s+com\.android\.systemui/\.keyguard\.KeyguardService\s+([a-f0-9]+)\s+pid=(\d+)\s+user=(\d+)',
        section_lines[0],
    )
    if not header_match:
        return None

    service_info = KeyguardServiceInfo()

    service_info.service_hash = header_match.group(1).strip()
    service_info.pid = int(header_match.group(2))
    service_info.user = int(header_match.group(3))

    in_unlock_info = False
    current_user_settings = None

    for line in section_lines[1:]:
        stripped_line = line.strip()
        if b"KeyguardUnlockInfo" in stripped_line:
            in_unlock_info = True
            continue
        elif stripped_line.startswith(b"User "):
            in_unlock_info = False
            user_match = re.search(rb'User\s+(\d+)', stripped_line)
            if user_match:
                current_user_settings = int(user_match.group(1))
                service_info.user_settings[current_user_settings] = {}
        elif in_unlock_info:
            log_match = re.match(
                rb'(\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3})\s+(.*)',
                stripped_line,
            )
            if log_match:
                service_info.unlock_info_log.append(
                    {
                        'timestamp': log_match.group(1),
                        'message': log_match.group(2),
                    }
                )
        elif current_user_settings is not None:
            if b':' in stripped_line:
                key, value = stripped_line.split(b':', 1)
                service_info.user_settings[current_user_settings][
                    key.strip()
                ] = value.strip()

    return service_info
