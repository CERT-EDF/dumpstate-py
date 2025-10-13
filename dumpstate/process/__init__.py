import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class ThreadInfo:
    """Represents a single thread line from a process dump."""

    # Common attributes
    pid: int = 0
    tid: int = 0
    user: bytes = b''
    name: bytes = b''
    state: bytes = b''
    cmd: bytes = b''

    # 'ps' specific attributes
    label: bytes = b''
    ppid: int = 0
    vsz: bytes = b''
    rss: bytes = b''
    wchan: bytes = b''
    addr: bytes = b''
    pri: bytes = b''
    ni: bytes = b''
    rtprio: bytes = b''
    sched: bytes = b''
    pcy: bytes = b''
    time: bytes = b''

    # 'top' specific attributes
    cpu_percent: float = 0.0
    virt: bytes = b''
    res: bytes = b''

    def parse(self, line: bytes, source: str):
        self._parsers = {'ps': self._parse_ps, 'top': self._parse_top}
        self._parse(line.strip(), source)

    def _parse(self, raw: bytes, source: str):
        """Parses a single process line based on its source."""
        parser_func = self._parsers.get(source)
        if parser_func:
            parser_func(raw)

    def _parse_ps(self, raw: bytes):
        """Parses a line from the 'ps' command output."""
        parts = raw.split()

        if len(parts) < 14:
            return

        (
            self.label,
            self.user,
            pid,
            tid,
            ppid,
            self.vsz,
            self.rss,
            self.wchan,
            self.addr,
            self.state,
            self.pri,
            self.ni,
            self.rtprio,
            self.sched,
            self.pcy,
            self.time,
            *cmd_parts,
        ) = parts
        self.pid = int(pid)
        self.tid = int(tid)
        self.ppid = int(ppid)
        self.name = b' '.join(cmd_parts)

    def _parse_top(self, raw: bytes):
        """Parses a line from the 'top' command output."""
        parts = raw.split()
        if len(parts) < 12:
            return
        self.pid = int(parts[0])
        self.tid = int(parts[1])
        self.user = parts[2]
        self.pr = parts[3]
        self.ni = parts[4]
        self.cpu_percent = float(parts[5].replace(b'%', b''))
        self.state = parts[6]
        self.virt = parts[7]
        self.res = parts[8]
        self.pcy = parts[9]
        self.cmd = parts[10]
        self.name = b' '.join(parts[11:])


@dataclass
class Process:
    """Represents a process and its threads."""

    pid: int
    user: bytes
    name: bytes
    threads: dict[int, ThreadInfo] = field(default_factory=dict)

    def add_thread(self, thread_info: ThreadInfo):
        if thread_info.tid not in self.threads:
            self.threads[thread_info.tid] = thread_info
        else:
            # Merge data from different sources (ps and top)
            for key, value in thread_info.__dict__.items():
                if value is not None:
                    setattr(self.threads[thread_info.tid], key, value)


@dataclass
class ProcessReport:
    """Represents the combined process and CPU info."""

    threads_summary: dict = field(default_factory=dict)
    mem_summary: dict = field(default_factory=dict)
    swap_summary: dict = field(default_factory=dict)
    cpu_summary: dict = field(default_factory=dict)
    processes: dict[int, Process] = field(default_factory=dict)


def _parse_top_content(info: ProcessReport, lines: list[bytes]):
    """Helper to parse the content of the CPU INFO section."""
    for line in lines:
        if line.startswith(b'Threads:'):
            parts = re.findall(rb'(\d+)\s+(\w+)', line)
            info.threads_summary = {
                status: int(count) for count, status in parts
            }
        elif line.startswith(b'  Mem:'):
            parts = re.findall(rb'(\d+K)\s+(\w+)', line)
            info.mem_summary = {status: size for size, status in parts}
        elif line.startswith(b' Swap:'):
            parts = re.findall(rb'(\d+K)\s+(\w+)', line)
            info.swap_summary = {status: size for size, status in parts}
        elif line.startswith(b'800%cpu'):
            cpu_parts = re.findall(rb'(\d+%)([^%\s]+)', line)
            info.cpu_summary = {status: value for value, status in cpu_parts}

    process_lines_started = False
    for line in lines:
        if line.strip().startswith(b'PID   TID'):
            process_lines_started = True
            continue
        if process_lines_started:
            thread_info = ThreadInfo()
            thread_info.parse(line, 'top')
            if not thread_info.pid:
                continue
            if thread_info.pid not in info.processes:
                info.processes[thread_info.pid] = Process(
                    thread_info.pid, thread_info.user, thread_info.name
                )
            info.processes[thread_info.pid].add_thread(thread_info)


def _parse_ps_content(info: ProcessReport, lines: list[bytes]):
    """Helper to parse the content of the PROCESSES AND THREADS section."""
    process_lines_started = False
    for line in lines:
        if line.strip().startswith(b'LABEL'):
            process_lines_started = True
            continue
        if process_lines_started:
            thread_info = ThreadInfo()
            thread_info.parse(line, 'ps')
            if not thread_info.pid:
                continue
            if thread_info.pid not in info.processes:
                info.processes[thread_info.pid] = Process(
                    thread_info.pid, thread_info.user, thread_info.name
                )
            info.processes[thread_info.pid].add_thread(thread_info)


def parse_process_info(dumpstate_content: RawData):
    """Parses and merges 'CPU INFO' and 'PROCESSES AND THREADS' sections by iterating through lines."""
    LOGGER.info("Parsing \"CPU INFO and PROCESSES AND THREADS\" section...")

    info = ProcessReport()

    section_lines: dict[str, list[bytes]] = {}
    current_section = None

    for line in dumpstate_content.lines:
        if line.startswith(b'----- CPU INFO'):
            current_section = 'cpu'
            section_lines[current_section] = []
        elif line.startswith(b'------ PROCESSES AND THREADS'):
            current_section = 'ps'
            section_lines[current_section] = []
        elif line.startswith(b'------ ') and b'was the duration of' in line:
            current_section = None
        elif current_section:
            section_lines[current_section].append(line)

    if 'cpu' in section_lines:
        _parse_top_content(info, section_lines['cpu'])

    if 'ps' in section_lines:
        _parse_ps_content(info, section_lines['ps'])

    return info if info.processes else None
