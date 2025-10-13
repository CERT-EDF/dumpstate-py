# dumpstate-py

<p align="center"><img width="120" src="./.github/logo.png"></p>
<h2 align="center">Dumpstate-PY</h2>

<div align="center">

![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)
![Powered By: EDF](https://img.shields.io/badge/Powered_By-CERT_EDF-FFFF33.svg?style=for-the-badge)
[![License: APACHE 2.0](https://img.shields.io/badge/License-APACHE_2.0-2596be.svg?style=for-the-badge)](LICENSE)

</div>

<br>

Android Dumpstate Parser is a pure Python package that extract useful information for forensic analysis, and depends only a classic [Android Bug Report](https://developer.android.com/studio/debug/bug-report) :
 - no specific permissions needed to extract system logs
 - parse only useful sections from the bug report
 - expose the information in simple structures in order to be used by external tools like [CERT-EDF/plasma](https://github.com/CERT-EDF/plasma)

## Currently supported sections

| Section               | Magic values                                         |
|:---------------------:|:-----------------------------------------------------|
| Header                | `== dumpstate:` |
| Battery               | `------ CHECKIN BATTERYSTATS` |
| Mount                 | `------ MOUNT POINT DUMP` |
| Netstat               | `------ NETSTAT` |
| Package               | `DUMP OF SERVICE package:`, `START INSTALL PACKAGE` and `START DELETE PACKAGE` |
| Process               | `----- CPU INFO` and `------ PROCESSES AND THREADS` |
| Power                 | `------ POWER OFF RESET REASON` |
| Account Service       | `DUMP OF SERVICE account:` |
| Keyguard Service      | `KeyguardService` |
| Crash Info            | `------ VM TRACES AT LAST ANR` and `------ ANR FILES (ls -lt /data/anr/) ------` |
| Loaded Kernel Modules | `------ LSMOD (lsmod)` |
| Network Socket State  | `------ DETAILED SOCKET STATE (ss -eionptu)` |
| Network Dev Info      | `------ NETWORK DEV INFO (/proc/net/dev) ` |
| GPS Coordinates       | `Fused Location Provider` |
| USB                   | `USB MANAGER STATE` |


## Setup

```bash
git clone https://github.com/cert-edf/dumpstate-py
cd dumpstate-py
python -m pip install -e .
```

## Usage

All fields in the `Dumpstate` object are available via dataclass directly, so it should be easy to use, and it should be the usage to be used in other tool directly.

Otherwise you can use the command line directly to see the information extracted via the tool, but it could be very verbose:

```bash
dumpstate dumpstate-2025-03-28-08-45-52.txt  -s kernel
```
```text
INFO     LoadedModule(name=b'wlan_drv_gen4m', size=3981312, used_by=[])
INFO     LoadedModule(name=b'wmt_chrdev_wifi', size=49152, used_by=[b'wlan_drv_gen4m'])
INFO     LoadedModule(name=b'gps_drv', size=528384, used_by=[])
INFO     LoadedModule(name=b'fmradio_drv_connac2x', size=196608, used_by=[])
INFO     LoadedModule(name=b'bt_drv_6877', size=270336, used_by=[])
INFO     LoadedModule(name=b'conninfra', size=286720, used_by=[b'wlan_drv_gen4m,wmt_chrdev_wifi,gps_drv,fmradio_drv_connac2x,bt_drv_6877'])
INFO     LoadedModule(name=b'connfem', size=40960, used_by=[b'wlan_drv_gen4m,bt_drv_6877'])
INFO     LoadedModule(name=b'trace_mmstat', size=20480, used_by=[])
```

## Interesting sections that could be parsed in the future

```
Known Packages:
In-memory monthly stats
------ USB LOG (/proc/usblog) ------
DUMP OF SERVICE wifiscanner:
DUMP OF SERVICE wifi:
DUMP OF SERVICE lock_settings:
DUMP OF SERVICE adb:
DUMP OF SERVICE appops:
------ VIRTUAL MEMORY STATS (/proc/vmstat) ------
DUMP OF SERVICE HIGH meminfo:
DUMP OF SERVICE HIGH network_stack:
DUMP OF SERVICE CRITICAL cpuinfo:
DUMP OF SERVICE CRITICAL power:
------ LOG STATISTICS (logcat -b all -S -g) ------
------ SYSTEM PROPERTIES (getprop) ------
------ POWER OFF RESET REASON (/data/log/power_off_reset_reason.txt: 2025-08-11 08:38:51) ------
------ PRINT LIST OF FILE IN /data/log (ls -a -l -R /data/log/) ------
------ PRINTENV (printenv) ------
------ BLOCKED PROCESS WAIT-CHANNELS ------
------ EBPF MAP STATS (/system/bin/dumpsys -T 30000 connectivity trafficcontroller) ------
------ NETWORK INTERFACES (ip link) ------
------ IPv4 ADDRESSES (ip -4 addr show) ------
------ IPv6 ADDRESSES (ip -6 addr show) ------
------ IP RULES (ip rule show) ------
------ IP RULES v6 (ip -6 rule show) ------
------ RT_TABLES (/data/misc/net/rt_tables: 2025-08-14 09:17:54) ------
------ ROUTE TABLE IPv4 (ip -4 route show table 255) ------
------ ROUTE TABLE IPv6 (ip -6 route show table 255) ------
SERVICE com.android.phone/.TelephonyDebugService
BUFFER BiometricLog:
BUFFER BluetoothLog:
BUFFER KeyguardLog:
==================== Basic dump state ====================
------ DUMPSYS (/system/bin/dumpsys -T 30000 android.security.authorization) ------
------ DUMPSYS (/system/bin/dumpsys -T 30000 lock_settings) ------
SemClientModeManager:
DUMP OF SERVICE app_binding:
DUMP OF SERVICE bluetooth_manager:
DUMP OF SERVICE carrier_config:
DUMP OF SERVICE content:
DUMP OF SERVICE device_policy:
DUMP OF SERVICE diskstats:
DUMP OF SERVICE firewall:
DUMP OF SERVICE settings:
```
