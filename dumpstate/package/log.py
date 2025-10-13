import re
from dataclasses import dataclass
from datetime import datetime

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class PackageInstallInfo:
    timestamp: datetime
    observer: str
    staged_dir: str
    package_name: str
    version_code: int
    request_from: str
    result: int = 0


@dataclass
class PackageDeleteInfo:
    timestamp: datetime
    observer: str
    package_name: str
    user: str
    caller: str
    result: int = 0


def parse_package_install_log(
    dumpstate_content: RawData,
) -> list[PackageInstallInfo | PackageDeleteInfo] | None:
    """Parses package installation and deletion logs."""
    LOGGER.info("Parsing \"INSTALL PACKAGE\" section...")

    log_data: list[InstallLogEntry] = []

    def get_key_val(text: bytes) -> tuple[bytes | None, bytes | None] | None:
        match = re.search(b'(.*?){(.*?)}', text)
        if not match:
            return None
        return match.group(1), match.group(2)

    def get_val(text: bytes, key: bytes) -> bytes:
        match = re.search(key + b'{(.*?)}', text)
        return match.group(1) if match else b''

    in_section = 0
    current_observer: bytes = b''
    sections = {}

    for line in dumpstate_content.lines:
        if b"START INSTALL PACKAGE" in line:
            current_observer = get_val(line, b"observer")

            ts_match = re.match(
                r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}):\s',
                line.decode('utf-8'),
            )
            if ts_match:
                in_section = 4
                timestamp = datetime.strptime(
                    ts_match.group(1), '%Y-%m-%d %H:%M:%S.%f'
                )
                sections[current_observer] = {
                    "type": "INSTALL",
                    "timestamp": timestamp,
                    "data": [],
                    "result": [],
                }

        elif b"START DELETE PACKAGE" in line:
            current_observer = get_val(line, b"observer")
            ts_match = re.match(
                r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}):\s',
                line.decode('utf-8'),
            )
            if ts_match:
                in_section = 1
                timestamp = datetime.strptime(
                    ts_match.group(1), '%Y-%m-%d %H:%M:%S.%f'
                )
                sections[current_observer] = {
                    "type": "DELETE",
                    "timestamp": timestamp,
                    "data": [],
                    "result": [],
                }
        else:
            if current_observer and in_section:
                in_section -= 1
                sections[current_observer]["data"].append(line.lstrip())
            else:
                if (b"result of install" in line) or (
                    b"result of delete" in line
                ):
                    ts_match = re.match(
                        r'(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\.\d{3}):\s',
                        line.decode('utf-8'),
                    )
                    if ts_match:
                        line_content = line[ts_match.end() :]
                        match = re.match(
                            r'result of (\w+):\s(-?\d+){(\d+)}',
                            line_content.decode('utf-8'),
                        )
                        if match:
                            action = match.group(1)
                            result_code = int(match.group(2))
                            observer = match.group(3).encode('utf-8')

                            # Multi package
                            if observer not in sections:
                                continue

                            sections[observer]["result"] = [
                                action,
                                result_code,
                            ]

    for key in sections:
        if sections[key]["type"] == "INSTALL":
            details = {}
            for line in sections[key]["data"]:
                key_value, val = get_key_val(line)
                details[key_value] = val

            pii = PackageInstallInfo(
                sections[key]["timestamp"],
                key,
                details[b'stagedDir'].decode('utf-8'),
                details[b'pkg'].decode('utf-8'),
                int(details[b'versionCode']),
                details[b'Request from'].decode('utf-8'),
            )
            pii.result = sections[key]["result"][1]
            log_data.append(pii)
        elif sections[key]["type"] == "DELETE":
            details = {}

            for line in sections[key]["data"]:
                for details_line in line.split(b', '):
                    key_value, val = get_key_val(details_line)
                    details[key_value] = val

            pdi = PackageDeleteInfo(
                sections[key]["timestamp"],
                key,
                details[b'pkg'].decode('utf-8'),
                details[b'user'].decode('utf-8'),
                details[b'caller'].decode('utf-8'),
            )
            pdi.result = sections[key]["result"][1]
            log_data.append(pdi)
    return log_data
