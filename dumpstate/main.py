"""Dumpstate entrypoint"""

from argparse import ArgumentParser
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, is_zipfile

from . import (
    SECTION_ACCOUNT,
    SECTION_BATTERY,
    SECTION_CRASH,
    SECTION_GPS,
    SECTION_HEADER,
    SECTION_KERNEL,
    SECTION_KEYGUARD,
    SECTION_MOUNT,
    SECTION_PACKAGE,
    SECTION_POWER,
    SECTION_PROCESS,
    SECTION_SOCKET,
    SECTION_USB,
    SECTIONS,
    Dumpstate,
)
from .helper.logging import LOGGER


def _header(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.header_log)


def _mount(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.mount_points_log)


def _crash(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.vm_traces_log)
    LOGGER.info(dumpstate.anr_files_log)


def _kernel(dumpstate: Dumpstate):
    for kernel_module in dumpstate.loaded_modules_log:
        LOGGER.info(kernel_module)


def _gps(dumpstate: Dumpstate):
    if dumpstate.gps_data_log:
        for gps_data in dumpstate.gps_data_log:
            LOGGER.info(gps_data)


def _package(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.package_info_log)
    for package_info in dumpstate.package_install_log:
        LOGGER.info(package_info)


def _process(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.process_info_log)


def _socket(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.socket_netstat_log)
    LOGGER.info(dumpstate.socket_ss_log)
    LOGGER.info(dumpstate.socket_dev_log)


def _power(dumpstate: Dumpstate):
    if dumpstate.power_info_log:
        for power_event in dumpstate.power_info_log:
            LOGGER.info(power_event)


def _usb(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.usb_data_log)


def _battery(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.battery_stats_log)


def _account(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.account_service_log)


def _keyguard(dumpstate: Dumpstate):
    LOGGER.info(dumpstate.keyguard_service_log)


_SECTION_STRATEGY = {
    SECTION_HEADER: _header,
    SECTION_MOUNT: _mount,
    SECTION_CRASH: _crash,
    SECTION_KERNEL: _kernel,
    SECTION_GPS: _gps,
    SECTION_PACKAGE: _package,
    SECTION_PROCESS: _process,
    SECTION_SOCKET: _socket,
    SECTION_POWER: _power,
    SECTION_USB: _usb,
    SECTION_BATTERY: _battery,
    SECTION_ACCOUNT: _account,
    SECTION_KEYGUARD: _keyguard,
}


def init_parser():
    """Init argv parser"""
    parser = ArgumentParser(
        description="Dumpstate Android Parser: extract data from usefull sections"
    )
    parser.add_argument(
        'input', type=Path, help='input bug report file (dumpstate)'
    )
    parser.add_argument(
        '-s',
        '--sections',
        choices=SECTIONS,
        nargs='+',
        help='sections to display',
    )
    return parser.parse_args()


def app():
    """Application entrypoint"""
    args = init_parser()
    dumpstate_bytes = None

    if is_zipfile(args.input):
        with ZipFile(args.input, 'r') as zip_obj:
            for file_name in zip_obj.namelist():
                if "dumpstate-" in file_name:
                    dumpstate_bytes = zip_obj.read(file_name)
    else:
        with open(args.input, 'rb') as fd:
            dumpstate_bytes = fd.read()

    sections = args.sections or SECTIONS

    dumpstate = Dumpstate()
    dumpstate.parse(
        BytesIO(dumpstate_bytes),
        sections={
            section: False for section in SECTIONS if section not in sections
        },
    )

    for section in sections:
        _SECTION_STRATEGY[section](dumpstate)

    return 0


if __name__ == '__main__':
    app()
