import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class Socket:
    """Represents a single socket connection."""

    netid: bytes = b''
    state: bytes = b''
    recv_q: int = 0
    send_q: int = 0
    local_address: bytes = b''
    local_port: bytes = b''
    peer_address: bytes = b''
    peer_port: bytes = b''
    uid: int = 0
    ino: int = 0
    sk: bytes = b''
    details: dict[bytes, bytes | int] = field(default_factory=dict)

    def parse(self, all_lines: bytes):
        """Parses a single socket line."""
        lines = all_lines.split(b'\n')
        main_line = lines[0]

        parts = main_line.split()
        if len(parts) < 6:
            return

        self.netid = parts[0]
        self.state = parts[1]
        self.recv_q = int(parts[2])
        self.send_q = int(parts[3])

        local_addr_full = parts[4]
        peer_addr_full = parts[5]

        # Split address and port
        if b':' in local_addr_full:
            self.local_address, self.local_port = local_addr_full.rsplit(
                b':', 1
            )
        else:
            self.local_address = local_addr_full

        if b':' in peer_addr_full:
            self.peer_address, self.peer_port = peer_addr_full.rsplit(b':', 1)
        else:
            self.peer_address = peer_addr_full

        # Extract extra info
        for part in parts[6:]:
            if b'uid:' in part:
                self.uid = int(part.split(b':')[1])
            elif b'ino:' in part:
                self.ino = int(part.split(b':')[1])
            elif b'sk:' in part:
                self.sk = part.split(b':')[1]

        # The details are in the next line, if it's indented
        if len(lines) > 1:
            details_line = lines[1].strip()
            detail_parts = details_line.split()
            for part in detail_parts:
                if b':' in part:
                    key, value = part.split(b':', 1)
                    if value.decode("utf-8").isnumeric():
                        self.details[key] = int(value)
                    else:
                        self.details[key] = value


def parse_ss(dumpstate_content: RawData) -> list[Socket] | None:
    """Parses the 'DETAILED SOCKET STATE' section."""
    LOGGER.info("Parsing \"DETAILED SOCKET STATE\" section...")

    socket_section_match = re.search(
        rb'------ DETAILED SOCKET STATE \(ss -eionptu\) ------\n(.*?)\n------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not socket_section_match:
        return None

    socket_content = socket_section_match.group(1)
    sockets: list[Socket] = []

    full_lines: list[bytes] = []
    for line in socket_content.split(b'\n'):
        if line.startswith(b'\t'):
            full_lines[-1] += b'\n' + line
        else:
            full_lines.append(line)

    for line in full_lines:
        if not line.strip().startswith(b'Netid'):
            s = Socket()
            s.parse(line)
            sockets.append(s)
    return sockets
