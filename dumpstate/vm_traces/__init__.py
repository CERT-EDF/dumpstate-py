import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class StackFrame:
    """Represents a single frame in a thread's stack trace."""

    frame_type: bytes = b''
    method: bytes = b''
    file_loc: bytes = b''
    line_number: int = 0
    address: bytes = b''
    library: bytes = b''
    details: bytes = b''

    def parse(self, line: bytes, frame_type: bytes = b'managed'):
        self.frame_type = frame_type

        if frame_type == b'native':
            self._parse_native_frame(line.strip())
        else:
            self._parse_managed_frame(line.strip())

    def _parse_native_frame(self, raw: bytes):
        """Parses a native stack frame."""
        match = re.search(
            rb'#\d{2}\s+pc\s+([0-9a-fA-F]+)\s+([^\(]+)\s*\((.*?)\)', raw
        )
        if match:
            self.address = match.group(1)
            self.library = match.group(2).strip()
            self.details = match.group(3).strip()

    def _parse_managed_frame(self, raw: bytes):
        """Parses a managed (Java/Kotlin) stack frame."""
        self.method = raw.replace(b'at ', b'')
        match = re.search(rb'\(([^:]+):?(\d*)\)', self.method)
        if match:
            self.file_loc = match.group(1)
            if match.group(2):
                self.line_number = int(match.group(2))


@dataclass
class Thread:
    """Represents a single thread from the ANR trace."""

    name: bytes = b''
    priority: int = 0
    tid: int = 0
    status: bytes = b''
    is_daemon: bool = False
    properties: dict[str, bytes] = field(default_factory=dict)
    stack_trace: list[StackFrame] = field(default_factory=list)

    def parse(self, header_line: bytes):
        raw_header = header_line.strip()
        self.is_daemon = b"daemon" in raw_header
        self._parse_header(raw_header)

    def _parse_header(self, raw: bytes):
        """Parses the main thread header line."""
        match = re.search(
            rb'"([^"]+)"\s+(daemon\s+)?prio=(\d+)\s+tid=(\d+)\s+(.*)', raw
        )
        if match:
            self.name = match.group(1)
            self.priority = int(match.group(3))
            self.tid = int(match.group(4))
            self.status = match.group(5).strip()

    def add_property_line(self, line: bytes):
        """Adds a property line (lines starting with '|') to the thread."""
        parts = [p.strip() for p in line.strip().split(b'|') if p.strip()]
        for part in parts:
            if b'self=' in part:  # Special handling for self pointer
                key, value = 'self', part.split(b'self=')[1]
                self.properties[key] = value

            key_value_pairs = re.findall(rb'(\w+)=("([^"]*)"|([^\s]+))', part)
            for key, _, quoted_val, unquoted_val in key_value_pairs:
                self.properties[key] = (
                    quoted_val if quoted_val else unquoted_val
                )

    def add_stack_frame(self, frame: StackFrame):
        """Adds a StackFrame object to the thread's stack trace."""
        self.stack_trace.append(frame)


@dataclass
class AnrTrace:
    """Represents the entire 'VM TRACES AT LAST ANR' section."""

    header: dict[bytes, bytes] = field(default_factory=dict)
    process_info: dict[str, bytes | int] = field(default_factory=dict)
    threads: list[Thread] = field(default_factory=list)


def parse_anr_traces(dumpstate_content: RawData) -> AnrTrace | None:
    """
    Parses the 'VM TRACES AT LAST ANR' section from a dumpstate file.

    Args:
        dumpstate_content: A string containing the content of the dumpstate file.

    Returns:
        An AnrTrace object, or None if the section is not found.
    """
    LOGGER.info("Parsing \"VM TRACES AT LAST ANR\" section...")

    anr_section_match = re.search(
        rb'------ VM TRACES AT LAST ANR .*? ------\n(.*?)\n----- end \d+ -----',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not anr_section_match:
        return None

    anr_content = anr_section_match.group(1)
    anr_trace = AnrTrace()
    current_thread = None

    lines = anr_content.split(b'\n')
    i = 0
    while i < len(lines):
        line = lines[i]

        # Parse ANR Header
        if line.startswith(b'Subject:'):
            anr_trace.header[b'subject'] = line.split(b':', 1)[1].strip()
        elif (
            b':' in line
            and b'pid' not in line
            and not line.strip().startswith(b'|')
            and not line.strip().startswith(b'at ')
            and not line.strip().startswith(b'native:')
        ):
            if re.match(rb'^[A-Za-z]+.*?:', line):
                key, value = [x.strip() for x in line.split(b':', 1)]
                anr_trace.header[key.lower().replace(b' ', b'_')] = value

        # Parse Process Info
        if line.startswith(b'----- pid'):
            match = re.search(rb'pid\s+(\d+)\s+at\s+(.*)', line)
            if match:
                anr_trace.process_info['pid'] = int(match.group(1))
                anr_trace.process_info['timestamp'] = match.group(2).strip()

        elif line.startswith(b'Cmd line:'):
            anr_trace.process_info['cmd_line'] = line.split(b':', 1)[1].strip()
        elif line.startswith(b'Build fingerprint:'):
            anr_trace.process_info['build_fingerprint'] = line.split(b':', 1)[
                1
            ].strip()
        elif line.startswith(b'ABI:'):
            anr_trace.process_info['abi'] = line.split(b':', 1)[1].strip()

        # Parse Threads
        if line.startswith(b'"'):
            if current_thread:
                anr_trace.threads.append(current_thread)
            current_thread = Thread()
            current_thread.parse(line)
        elif current_thread:
            if line.strip().startswith(b'|'):
                current_thread.add_property_line(line)
            elif line.strip().startswith(b'at '):
                sf = StackFrame()
                sf.parse(line, b'managed')
                current_thread.add_stack_frame(sf)
            elif line.strip().startswith(b'native:'):
                sf = StackFrame()
                sf.parse(lines[i].replace(b'native:', b'').strip(), b'native')
                current_thread.add_stack_frame(sf)
                # Look ahead for the rest of the native stack trace
                j = i + 1
                while j < len(lines) and lines[j].strip().startswith(
                    b'native: #'
                ):
                    sf = StackFrame()
                    sf.parse(
                        lines[j].replace(b'native:', b'').strip(), b'native'
                    )
                    current_thread.add_stack_frame(sf)
                    j += 1
                i = j - 1  # Move the outer loop's index forward
            elif b'held mutexes=' in line:
                # This is part of a property line but can be on its own line
                current_thread.add_property_line(b"| " + line.strip())

        i += 1

    if current_thread:
        anr_trace.threads.append(current_thread)

    return anr_trace
