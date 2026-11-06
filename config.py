"""
Settings required for main.py. Basically sets pass/fail state for each system check against baseline. Also maps NIST CSF to control systems
"""

import os

from dotenv import load_dotenv

load_dotenv(override=True)  # .env wins over any variable already set on the computer

# Maps machine names and IPs.
ENDPOINTS = [
    {"name": "Domain Controller", "ip": "10.0.2.3", "hostname": "LAB-DC01", "wazuh_name": "DC"},
    {"name": "Windows Server", "ip": "10.0.2.52", "hostname": "WindowsServer", "wazuh_name": "WindowsServ"},
    {"name": "Linux Server", "ip": "10.0.2.50", "hostname": "linuxserv", "wazuh_name": "Linuxserv"},
    {"name": "Linux Workstation", "ip": "10.0.2.51", "hostname": "linuxws", "wazuh_name": "LinuxWS"},
    {"name": "Windows Workstation", "ip": "10.0.2.55", "hostname": "DESKTOP-E92TKTR", "wazuh_name": "WindowWS"},
]

#  NIST CSF 2.0 subcategories each tool tests.
NIST_CSF = {
    "action1": "PR.PS-02",
    "cloudflare": "PR.AA-03",
    "nessus": "ID.RA-01",
    "wazuh": "DE.CM-09, PR.PS-01",
}

# Known Exceptions
EXPECTED_GAPS = {
    ("Domain Controller", "cloudflare"): "Cloudflare WARP is not supported on Windows Server",
    ("Windows Server", "cloudflare"): "Cloudflare WARP is not supported on Windows Server",
}

STALE_AFTER_MINUTES = {"action1": 120, "cloudflare": 60, "nessus": 1440, "wazuh": 15}

# Wazuh security configuration (SCA) score limits, and the maximum age of its scans.
SCA_FAIL_BELOW = 40
SCA_WARN_BELOW = 70
WAZUH_SCAN_STALE_MINUTES = 1440

# Non-critical updates to ignore per machine. This covers the Defender update
# KB4052623, which reappears after patching. Action1's summary gives counts, not
# names, so this ignores ANY one non-critical update on these machines.
ACTION1_TOLERATED_OTHER_UPDATES = {
    "Domain Controller": 1,
    "Windows Server": 1,
    "Windows Workstation": 1,
}

# The saved run that every later run is compared with.
BASELINE_FOLDER = os.environ.get("CCM_BASELINE_FOLDER", "BASELINE_ccm_report_20261029_203900")

# How far a number may move before it counts as a change. Wazuh's failed-check
# count moved by 1 to 2 between runs with nothing injected.
CHANGE_TOLERANCE = {"wazuh.sca_fail": 2}
