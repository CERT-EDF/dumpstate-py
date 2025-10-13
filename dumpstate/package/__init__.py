import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class Package:
    """Represents a single package from the package dump."""

    name: bytes = b''
    app_id: bytes = b''
    version_code: int = 0
    version_name: bytes = b''
    data_dir: bytes = b''
    flags: list[Any] = field(default_factory=list)
    private_flags: list[Any] = field(default_factory=list)
    users: dict[int, dict[str, bytes]] = field(default_factory=dict)
    runtime_permissions: dict[bytes, dict[str, Any]] = field(
        default_factory=dict
    )
    install_permissions: dict[bytes, dict[str, Any]] = field(
        default_factory=dict
    )
    declared_permissions: dict[bytes, dict[str, Any]] = field(
        default_factory=dict
    )
    first_install_time: bytes = b''
    originating_package_name: bytes = b''
    initiating_package_name: bytes = b''
    time_stamp: datetime = None
    last_update_time: datetime = None
    installer_package_uid: int = 0

    def is_installed_for_user(self, user_id: int):
        """Checks if the package is installed for a given user."""
        user_data: dict[str, bytes] | None = self.users.get(user_id)
        if user_data and 'raw' in user_data:
            return b'installed=true' in user_data['raw']
        return False


@dataclass
class PackageInfo:
    """Represents the DUMP OF SERVICE package section."""

    service_pid: int = 0
    threads_in_use: bytes = b''
    client_pids: list[int] = field(default_factory=list)
    database_versions: dict[bytes, bytes] = field(default_factory=dict)
    known_packages: dict[bytes, bytes] = field(default_factory=dict)
    verifiers: list[bytes] = field(default_factory=list)
    domain_verifier: bytes = b''
    libraries: dict[bytes, bytes] = field(default_factory=dict)
    features: list[bytes] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    permissions: list = field(default_factory=list)
    shared_users: list = field(default_factory=list)
    activity_resolver: dict = field(default_factory=dict)
    receiver_resolver: dict = field(default_factory=dict)
    service_resolver: dict = field(default_factory=dict)
    provider_resolver: dict = field(default_factory=dict)
    permission_trees: list = field(default_factory=list)
    package_changes: dict = field(default_factory=dict)
    install_sessions: list = field(default_factory=list)
    apex_session_state: dict = field(default_factory=dict)


def parse_package_info(dumpstate_content: RawData) -> PackageInfo | None:
    """Parses the 'DUMP OF SERVICE package' section."""
    LOGGER.info("Parsing \"DUMP OF SERVICE package\" section...")

    package_content_lines: list[bytes] = []
    in_package_section = False

    for line in dumpstate_content.lines:
        if line.startswith(b'DUMP OF SERVICE package:'):
            in_package_section = True
            continue

        if in_package_section:
            if line.startswith(b'DUMP OF SERVICE') or line.startswith(
                b'------'
            ):
                break
            package_content_lines.append(line)

    if not package_content_lines:
        return None

    package_content = b'\n'.join(package_content_lines)

    package_info = PackageInfo()
    current_section = None
    current_package = None
    current_package_subsection = None

    for line in package_content.split(b'\n'):
        non_stripped_line = line
        line = line.strip()
        if not line:
            continue

        # Section headers
        if line.startswith(b"Service host process PID:"):
            package_info.service_pid = int(line.split(b':')[1].strip())
        elif line.startswith(b"Threads in use:"):
            package_info.threads_in_use = line.split(b':')[1].strip()
        elif line.startswith(b"Client PIDs:"):
            pids_str = line.split(b':')[1].strip()
            package_info.client_pids = [int(p) for p in pids_str.split(b', ')]
        elif line.startswith(b"Database versions:"):
            current_section = 'database'
        elif line.startswith(b"Known Packages:"):
            current_section = 'known_packages'
        elif line.startswith(b"Verifiers:"):
            current_section = 'verifiers'
        elif line.startswith(b"Domain Verifier:"):
            current_section = 'domain_verifier'
        elif line.startswith(b"Libraries:"):
            current_section = 'libraries'
        elif line.startswith(b"Features:"):
            current_section = 'features'
        elif line.startswith(b"Packages:"):
            current_section = 'packages'
        elif re.match(rb'^[A-Z][a-zA-Z\s]+:', line):
            current_section = None

        elif current_section:
            if current_section == 'database':
                if b':' in line:
                    db_type, db_info = line.split(b':', 1)
                    package_info.database_versions[db_type.strip()] = (
                        db_info.strip()
                    )
            elif current_section == 'known_packages':
                if b':' in line:
                    pkg_type, pkg_name = line.split(b':', 1)
                    package_info.known_packages[pkg_type.strip()] = (
                        pkg_name.strip()
                    )
            elif current_section == 'verifiers':
                if line.startswith(b'Required:'):
                    package_info.verifiers.append(
                        line.replace(b'Required:', b'').strip()
                    )
            elif current_section == 'domain_verifier':
                if line.startswith(b'Using:'):
                    package_info.domain_verifier = line.replace(
                        b'Using:', b''
                    ).strip()
            elif current_section == 'libraries':
                if b'->' in line:
                    lib_name, lib_path = line.split(b'->', 1)
                    package_info.libraries[lib_name.strip()] = lib_path.strip()
            elif current_section == 'features':
                package_info.features.append(line)
            elif current_section == 'packages':
                if line.startswith(b'Package ['):
                    current_package = Package()
                    current_package_subsection = None
                    package_info.packages.append(current_package)

                    match = re.search(rb'Package \[([^\]]+)\]', line)
                    if match:
                        current_package.name = match.group(1)
                elif current_package:
                    if line.startswith(b'runtime permissions:'):
                        current_package_subsection = 'runtime_permissions'
                        continue
                    elif line.startswith(b'install permissions:'):
                        current_package_subsection = 'install_permissions'
                        continue
                    elif line.startswith(b'declared permissions:'):
                        current_package_subsection = 'declared_permissions'
                        continue

                    # If the line is not indented with at least 6 spaces, it's not part of a subsection
                    if not non_stripped_line.startswith(b'      '):
                        current_package_subsection = None

                    if current_package_subsection == 'runtime_permissions':
                        match = re.search(
                            rb'([^:]+):\s*granted=(true|false)(?:,\s*flags=\[(.*?)\])?',
                            line,
                        )
                        if match:
                            perm_name = match.group(1).strip()
                            granted = match.group(2) == b'true'
                            flags = (
                                [f.strip() for f in match.group(3).split(b'|')]
                                if match.group(3)
                                else []
                            )
                            current_package.runtime_permissions[perm_name] = {
                                'granted': granted,
                                'flags': flags,
                            }
                    elif current_package_subsection == 'install_permissions':
                        match = re.search(
                            rb'([^:]+): granted=(true|false)', line
                        )
                        if match:
                            perm_name = match.group(1).strip()
                            granted = match.group(2) == b'true'
                            current_package.install_permissions[perm_name] = {
                                'granted': granted
                            }
                    elif current_package_subsection == 'declared_permissions':
                        match = re.search(rb'([^:]+):\s*(prot=([^:]+))?', line)
                        if match:
                            perm_name = match.group(1).strip()
                            prot_value = match.group(3).strip()
                            current_package.declared_permissions[perm_name] = {
                                'prot': [
                                    f.strip() for f in prot_value.split(b'|')
                                ]
                            }
                    else:
                        if line.startswith(b'appId='):
                            current_package.app_id = line.split(b'=')[1]
                        elif b'versionCode=' in line:
                            match = re.search(rb'versionCode=(\d+)', line)
                            if match:
                                current_package.version_code = int(
                                    match.group(1)
                                )
                        elif b'versionName=' in line:
                            match = re.search(rb'versionName=([^\s]+)', line)
                            if match:
                                current_package.version_name = match.group(1)
                        elif line.startswith(b'dataDir='):
                            current_package.data_dir = line.split(b'=')[1]
                        elif line.startswith(b'flags='):
                            current_package.flags = re.findall(
                                rb'([A-Z_]+)', line
                            )
                        elif line.startswith(b'privateFlags='):
                            current_package.private_flags = re.findall(
                                rb'([A-Z_]+)', line
                            )
                        elif line.startswith(b'User '):
                            user_match = re.search(rb'User (\d+):', line)
                            if user_match:
                                user_id = int(user_match.group(1))
                                current_package.users[user_id] = {'raw': line}
                                install_time_match = re.search(
                                    rb'firstInstallTime=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
                                    line,
                                )
                                if install_time_match:
                                    current_package.first_install_time = (
                                        install_time_match.group(1)
                                    )
                        elif line.startswith(b'originatingPackageName'):
                            current_package.originating_package_name = (
                                line.split(b'=')[1]
                            )
                        elif line.startswith(b'initiatingPackageName'):
                            current_package.initiating_package_name = (
                                line.split(b'=')[1]
                            )
                        elif line.startswith(b'installerPackageUid'):
                            current_package.installer_package_uid = int(
                                line.split(b'=')[1]
                            )
                        elif line.startswith(b'timeStamp'):
                            timestamp_str = line.split(b'=')[1].decode('utf-8')
                            current_package.time_stamp = datetime.strptime(
                                timestamp_str, "%Y-%m-%d %H:%M:%S"
                            )
                        elif line.startswith(b'lastUpdateTime'):
                            timestamp_str = line.split(b'=')[1].decode('utf-8')
                            current_package.last_update_time = (
                                datetime.strptime(
                                    timestamp_str, "%Y-%m-%d %H:%M:%S"
                                )
                            )

    return package_info
