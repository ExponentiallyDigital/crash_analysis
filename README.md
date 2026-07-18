# README.md

[![Release](https://img.shields.io/github/v/release/ExponentiallyDigital/crash_analysis?style=flat-square&color=blue)](https://github.com/ExponentiallyDigital/pia-wireguard-cfg/releases)
[![Windows](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/)
[![License](https://img.shields.io/github/license/ExponentiallyDigital/crash_analysis?style=flat-square)](https://github.com/ExponentiallyDigital/crash_analysis/blob/main/LICENSE)
[![Downloads](https://img.shields.io/github/downloads/ExponentiallyDigital/crash_analysis/total?style=flat-square&color=success)](https://github.com/ExponentiallyDigital/crash_analysis/releases)
![Visitor Count](https://visitor-badge.laobi.icu/badge?page_id=ExponentiallyDigital.crash_analysis)
[![Total Commits](https://img.shields.io/github/commit-activity/t/ExponentiallyDigital/crash_analysis?style=flat-square&color=blueviolet)](https://github.com/ExponentiallyDigital/crash_analysis/commits/main)
[![Top Language](https://img.shields.io/github/languages/top/ExponentiallyDigital/crash_analysis?style=flat-square&color=orange)](https://github.com/ExponentiallyDigital/crash_analysis)
[![Last Commit](https://img.shields.io/github/last-commit/ExponentiallyDigital/crash_analysis?style=flat-square&color=important)](https://github.com/ExponentiallyDigital/crash_analysis/commits/main)
[![Code Size](https://img.shields.io/github/languages/code-size/ExponentiallyDigital/crash_analysis?style=flat-square&color=lightgrey)](https://github.com/ExponentiallyDigital/crash_analysis)

Tools to assist with computer stability troublshooting, 'crash_analysis'.

> [!WARNING]
> Understand what these scripts do before use!

## Contents of this repo:

| Filename                             | Comment                                                                                                                                                                                                                                                                                                                          |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cleanup_task_schedule.ps1            | find and prompt to remove 'ghost' scheduled tasks                                                                                                                                                                                                                                                                                |
| cleanup_windows_services.ps1         | find and prompt to remove 'ghost' services tasks, run as admin                                                                                                                                                                                                                                                                   |
| ddr5_analyzer.py                     | automate RAM analysis from files created by ddr5_analyzer-extract_advanced.txt - Cross-Dump Physical Memory Diff, Page Table Chain Validation, Pool Header & Object Forensics", Bit-Flip Signature Extraction, Adjacent Row Ghost Hunting, Timer/DPC Correlation": analyze_timer_dpc(analyses), and PFN State & Entropy Analysis |
| ddr5_analyzer-extract_advanced.txt   | windebug command file to generate data for ddr5_analyzer.py from MEMORY.dmp files                                                                                                                                                                                                                                                |
| driver_test_phases.ps1               | menu driven set up for driver verifier testing, requires editing before use!                                                                                                                                                                                                                                                     |
| find_asus_all.ps1                    | scan file system for all ASUS drivers installed on the system                                                                                                                                                                                                                                                                    |
| find_asus_drivers.ps1                | search the Windows Driver Store for orphaned INF files referencing ASUS                                                                                                                                                                                                                                                          |
| handles-top10.ps1                    | display top 10 processes by number of handles                                                                                                                                                                                                                                                                                    |
| handle_count.py                      | display the total number of handles open, reads from perflog .json file, edit before use                                                                                                                                                                                                                                         |
| handle_visualisation.py              | read a json perffile and visually display handles in use, edit before use                                                                                                                                                                                                                                                        |
| leak_dashboard.ps1                   | handle leakage decetction, shows top handle users                                                                                                                                                                                                                                                                                |
| leak_data_logging.ps1                | capture data for memory leak analysis                                                                                                                                                                                                                                                                                            |
| leak_data_logging_analysis_v3.ps1    | enhanced performance counter analysis for detecting leaks and system issues                                                                                                                                                                                                                                                      |
| leak_data_logging_convert_to_csv.ps1 | performance Log JSON to CSV with Process Identity Tracking (v7) , edit before use                                                                                                                                                                                                                                                |
| leak_data_logging_pre_analysis.ps1   | extract a subset of perf data from a CSV file, edit before use                                                                                                                                                                                                                                                                   |
| master_testing.ps1                   | **Master testing** - set up testing & spawns '.\verifier_status.ps1', '.\leak_data_logging.ps1' and '.\poolmon_snapshot.ps1'                                                                                                                                                                                                     |
| poolmon_analysis.ps1                 | comprehensive temporal analysis of poolmon snapshots, edit before use                                                                                                                                                                                                                                                            |
| poolmon_analysis2.ps1                | OPTIMISED version for large datasets, comprehensive temporal analysis of poolmon snapshots, edit before use                                                                                                                                                                                                                      |
| poolmon_snapshot.ps1                 | capture raw poolmon data at regular intervals for later analysis, edit before use                                                                                                                                                                                                                                                |
| python_test.py                       | crude/basic test for Python set up/working                                                                                                                                                                                                                                                                                       |
| secure_kernel_monitor.ps1            | monitor system state to correlate with secure kernel crashes, edit before use                                                                                                                                                                                                                                                    |
| start_secure_kernel_trace.ps1        | start Windows Performance Recorder trace for secure kernel debugging, edit before use                                                                                                                                                                                                                                            |
| uptime_win.ps1                       | realtime applet that displays on VDU2 (editable): uptime, boot time, time to crash (edit this) RAM, handles, and threads, edit before use                                                                                                                                                                                        |
| verifier_status.ps1                  | generate MS Driver Verrifier report of current status                                                                                                                                                                                                                                                                            |
| windbg-analysis - single dump.ps1    | single input file version of 'windbg-analysis.ps'                                                                                                                                                                                                                                                                                |
| windbg-analysis.ps1                  | automate extraction of valuable data from MEMORY.dmp file(s) - 19 parameters extracted, avoid having to keep full memory dump files, can operate on multiple dump files, edit before use                                                                                                                                         |

Several scripts require set up as noted above, look for these placeholders:

```text
# !!!!!!!!!!!!!
# !!!!!!!!!!!!! edit below line:
# !!!!!!!!!!!!!
```

---

## Donations

Kindly consider a [PayPal](https://www.paypal.com/donate/?hosted_button_id=QJYPGRLG2RPBS) or [Patreon](https://www.patreon.com/cw/ExponentiallyDigital) donation to help support development.

---

## Support

These tools are **unsupported** and may cause objects in mirrors to be closer than they appear. Batteries not included.

---

## License

These programs are free software: you can redistribute them and/or modify them under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

These programs are distributed in the hope that they will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Copyright (C) 2026 Andrew Newbury.
