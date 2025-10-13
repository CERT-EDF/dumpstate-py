from dataclasses import dataclass
from io import BytesIO

from .battery import BatteryStats, parse_battery_stats
from .gps.fused import FusedLocationData, parse_fused_location
from .header import DumpstateHeader, parse_dumpstate_header
from .helper import RawData
from .helper.logging import LOGGER
from .kernel.lsmod import LoadedModule, parse_lsmod
from .mount import MountPoint, parse_mount_points
from .package import PackageInfo, parse_package_info
from .package.log import (
    PackageDeleteInfo,
    PackageInstallInfo,
    parse_package_install_log,
)
from .power import PowerEvent, parse_power_off_reset_reason
from .process import ProcessReport, parse_process_info
from .services.account import AccountInfo, parse_account_service
from .services.keyguard import KeyguardServiceInfo, parse_keyguard_service
from .socket.dev import NetworkDevInfoData, parse_network_dev_info
from .socket.netstat import Netstat, parse_netstat
from .socket.ss import Socket, parse_ss
from .usb import UsbManagerData, parse_usb_manager_state
from .vm_traces import AnrTrace, parse_anr_traces
from .vm_traces.anr_files import AnrFileData, parse_anr_files

SECTION_HEADER = 'header'
SECTION_MOUNT = 'mount'
SECTION_CRASH = 'crash'
SECTION_KERNEL = 'kernel'
SECTION_GPS = 'gps'
SECTION_PACKAGE = 'package'
SECTION_PROCESS = 'process'
SECTION_SOCKET = 'socket'
SECTION_POWER = 'power'
SECTION_USB = 'usb'
SECTION_BATTERY = 'battery'
SECTION_ACCOUNT = 'account'
SECTION_KEYGUARD = 'keyguard'


SECTIONS = (
    SECTION_HEADER,
    SECTION_MOUNT,
    SECTION_CRASH,
    SECTION_KERNEL,
    SECTION_GPS,
    SECTION_PACKAGE,
    SECTION_PROCESS,
    SECTION_SOCKET,
    SECTION_POWER,
    SECTION_USB,
    SECTION_BATTERY,
    SECTION_ACCOUNT,
    SECTION_KEYGUARD,
)


@dataclass
class Dumpstate:
    """Dumpstate parser"""

    _raw_data: RawData | None = None
    header_log: DumpstateHeader | None = None
    vm_traces_log: AnrTrace | None = None
    anr_files_log: AnrFileData | None = None
    gps_data_log: list[FusedLocationData] | None = None
    usb_data_log: UsbManagerData | None = None
    mount_points_log: list[MountPoint] | None = None
    package_info_log: PackageInfo | None = None
    package_install_log: (
        list[PackageInstallInfo | PackageDeleteInfo] | None
    ) = None
    process_info_log: ProcessReport | None = None
    battery_stats_log: BatteryStats | None = None
    socket_ss_log: list[Socket] | None = None
    socket_netstat_log: Netstat | None = None
    socket_dev_log: list[NetworkDevInfoData] | None = None
    account_service_log: AccountInfo | None = None
    keyguard_service_log: KeyguardServiceInfo | None = None
    loaded_modules_log: list[LoadedModule] | None = None
    power_info_log: list[PowerEvent] | None = None

    def parse(self, raw: BytesIO, sections: dict[str, bool] = None):
        """Parse dumpstate"""
        self._raw_data = RawData(raw.read())
        sections = sections or {}

        # Parse interesting and desired sections
        if sections.get(SECTION_HEADER, True):
            self.header_log = parse_dumpstate_header(self._raw_data)

        if sections.get(SECTION_CRASH, True):
            self.vm_traces_log = parse_anr_traces(self._raw_data)
            self.anr_files_log = parse_anr_files(self._raw_data)

        if sections.get(SECTION_GPS, True):
            self.gps_data_log = parse_fused_location(self._raw_data)

        if sections.get(SECTION_USB, True):
            self.usb_data_log = parse_usb_manager_state(self._raw_data)

        if sections.get(SECTION_MOUNT, True):
            self.mount_points_log = parse_mount_points(self._raw_data)

        if sections.get(SECTION_PACKAGE, True):
            self.package_info_log = parse_package_info(self._raw_data)
            self.package_install_log = parse_package_install_log(
                self._raw_data
            )

        if sections.get(SECTION_PROCESS, True):
            self.process_info_log = parse_process_info(self._raw_data)

        if sections.get(SECTION_BATTERY, True):
            self.battery_stats_log = parse_battery_stats(self._raw_data)

        if sections.get(SECTION_SOCKET, True):
            self.socket_ss_log = parse_ss(self._raw_data)
            self.socket_netstat_log = parse_netstat(self._raw_data)
            self.socket_dev_log = parse_network_dev_info(self._raw_data)

        if sections.get(SECTION_ACCOUNT, True):
            self.account_service_log = parse_account_service(self._raw_data)

        if sections.get(SECTION_KEYGUARD, True):
            self.keyguard_service_log = parse_keyguard_service(self._raw_data)

        if sections.get(SECTION_KERNEL, True):
            self.loaded_modules_log = parse_lsmod(self._raw_data)

        if sections.get(SECTION_POWER, True):
            self.power_info_log = parse_power_off_reset_reason(self._raw_data)
