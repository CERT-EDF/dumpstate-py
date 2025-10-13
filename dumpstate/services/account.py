import re
from dataclasses import dataclass, field

from dumpstate.helper import RawData
from dumpstate.helper.logging import LOGGER


@dataclass
class UserAccount:
    """Represents a user's account information."""

    user_info_raw: bytes = b''
    user_id: int = 0
    user_name: bytes = b''
    user_flag: bytes = b''
    accounts: list[bytes] = field(default_factory=list)
    accounts_history: list[bytes] = field(default_factory=list)
    active_sessions: int = 0
    registered_services: list[bytes] = field(default_factory=list)
    account_visibility: dict[bytes, list[bytes]] = field(default_factory=dict)


@dataclass
class AccountInfo:
    """Represents the DUMP OF SERVICE account section."""

    service_pid: int = 0
    threads_in_use: bytes = b''
    client_pids: list[int] = field(default_factory=list)
    users: list[UserAccount] = field(default_factory=list)


def parse_account_service(dumpstate_content: RawData):
    """Parses the 'DUMP OF SERVICE account' section."""
    LOGGER.info("Parsing \"SERVICE account\" section...")

    account_section_match = re.search(
        rb'DUMP OF SERVICE account:\n(.*?)\n---------',
        dumpstate_content.raw,
        re.DOTALL,
    )
    if not account_section_match:
        return None

    account_content = account_section_match.group(1)
    account_info = AccountInfo()
    current_user = None
    parsing_section = None
    current_visibility_account = None

    for line in account_content.strip().split(b'\n'):
        line = line.strip()
        if not line:
            continue

        if line.startswith(b'Service host process PID:'):
            account_info.service_pid = int(line.split(b':')[1].strip())
        elif line.startswith(b'Threads in use:'):
            account_info.threads_in_use = line.split(b':')[1].strip()
        elif line.startswith(b'Client PIDs:'):
            pids_str = line.split(b':')[1].strip()
            account_info.client_pids = [int(p) for p in pids_str.split(b', ')]
        elif line.startswith(b'User UserInfo'):
            if current_user:
                account_info.users.append(current_user)
            current_user = UserAccount()
            current_user.user_info_raw = line.split(b':', 1)[1].strip()

            match = re.search(rb'UserInfo\{(\d+):([^:]+):([^}]+)\}', line)
            if match:
                current_user.user_id = int(match.group(1))
                current_user.user_name = match.group(2)
                current_user.user_flag = match.group(3)
            parsing_section = None
            current_visibility_account = None
        elif current_user:
            if b"Accounts:" in line:
                parsing_section = 'accounts'
            elif b"Accounts History" in line:
                parsing_section = 'history'
            elif b"Active Sessions:" in line:
                parsing_section = 'sessions'
                current_user.active_sessions = int(line.split(b':')[1].strip())
            elif b"RegisteredServicesCache:" in line:
                parsing_section = 'services'
            elif b"Account visibility:" in line:
                parsing_section = 'visibility'
            elif line.startswith(b"---------"):
                parsing_section = None
            elif parsing_section:
                if parsing_section == 'accounts' and line.startswith(
                    b'Account {'
                ):
                    current_user.accounts.append(line)
                elif parsing_section == 'history' and not line.startswith(
                    b'AccountId,'
                ):
                    current_user.accounts_history.append(line)
                elif parsing_section == 'services' and line.startswith(
                    b'ServiceInfo:'
                ):
                    current_user.registered_services.append(line)
                elif parsing_section == 'visibility':
                    if current_visibility_account:
                        current_user.account_visibility[
                            current_visibility_account
                        ].append(line.strip())

                    elif not line.startswith(b' '):
                        current_visibility_account = line.strip()
                        current_user.account_visibility[
                            current_visibility_account
                        ] = []

    if current_user:
        account_info.users.append(current_user)

    return account_info
