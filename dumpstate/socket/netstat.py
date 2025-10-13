import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class InternetConnection:
    """Represents an active Internet connection."""

    proto: bytes = b''
    recv_q: bytes = b''
    send_q: bytes = b''
    local_address: bytes = b''
    foreign_address: bytes = b''
    state: bytes = b''
    user: bytes = b''
    inode: bytes = b''
    pid_program: bytes = b''

    def parse(self, raw: bytes):
        parts = raw.strip().split()
        if len(parts) < 6:
            return
        self.proto = parts[0]
        self.recv_q = parts[1]
        self.send_q = parts[2]
        self.local_address = parts[3]
        self.foreign_address = parts[4]
        self.state = parts[5]
        if len(parts) > 6:
            self.user = parts[6]
        if len(parts) > 7:
            self.inode = parts[7]
        if len(parts) > 8:
            self.pid_program = b' '.join(parts[8:])


@dataclass
class UnixSocket:
    """Represents an active UNIX domain socket."""

    proto: bytes = b''
    ref_cnt: bytes = b''
    flags: bytes = b''
    s_type: bytes = b''
    state: bytes = b''
    inode: bytes = b''
    pid_program: bytes = b''
    path: bytes = b''

    def parse(self, raw: bytes):
        """Parses a single line from the unix socket dump."""
        parts = raw.strip().split()
        if len(parts) < 6:
            return

        self.proto = parts.pop(0)
        self.ref_cnt = parts.pop(0)

        # Handle flags like [ ACC ] which can be split
        if parts[0].startswith(b'['):
            flags_parts: list[bytes] = []
            while parts:
                part = parts.pop(0)
                flags_parts.append(part)
                if part.endswith(b']'):
                    break
            self.flags = b' '.join(flags_parts)
        else:
            self.flags = parts.pop(0)

        self.s_type = parts.pop(0)
        self.state = parts.pop(0)
        self.inode = parts.pop(0)

        # The rest is PID/Program Name and Path. Path is always last if it exists.
        remaining_str = b' '.join(parts)

        path_match = re.search(rb'((?:[/@]\S+)\s*)$', remaining_str)
        if path_match:
            self.path = path_match.group(1).strip()
            pid_program_str = remaining_str[: path_match.start()].strip()
            self.pid_program = pid_program_str if pid_program_str else None
        else:
            self.path = None
            pid_program_str = remaining_str.strip()
            self.pid_program = pid_program_str if pid_program_str else None


@dataclass
class Netstat:
    """Represents the NETSTAT section."""

    internet_connections: list[InternetConnection] = field(
        default_factory=list
    )
    unix_sockets: list[UnixSocket] = field(default_factory=list)


def parse_netstat(dumpstate_content: RawData) -> Netstat | None:
    """Parses the 'NETSTAT' section."""
    LOGGER.info("Parsing \"NETSTAT\" section...")

    netstat_section_match = re.search(
        rb'------ NETSTAT \(.*?\) ------\n(.*?)\n------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not netstat_section_match:
        return None

    netstat_content = netstat_section_match.group(1)
    netstat = Netstat()
    parsing_mode = None  # Can be 'internet' or 'unix'

    for line in netstat_content.strip().split(b'\n'):
        line = line.strip()
        if not line:
            continue

        if b"Active Internet connections" in line:
            parsing_mode = b'internet'
            continue
        elif b"Active UNIX domain sockets" in line:
            parsing_mode = b'unix'
            continue
        elif line.startswith(b"Proto"):
            continue  # Skip header lines

        if parsing_mode == b'internet':
            ic = InternetConnection()
            ic.parse(line)
            netstat.internet_connections.append(ic)
        elif parsing_mode == b'unix':
            us = UnixSocket()
            us.parse(line)
            netstat.unix_sockets.append(us)

    return netstat
