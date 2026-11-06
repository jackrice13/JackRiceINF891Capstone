"""
Collects control data from APIs, outputs to CSV/json
"""

import os

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = (10, 60)  # seconds to connect, seconds to wait for a reply
CLOUDFLARE_URL = "https://api.cloudflare.com/client/v4"


def get_json(url, headers, params=None, verify=True):
    """Sends one GET request and returns the JSON reply. Any HTTP error raises."""
    response = requests.get(url, headers=headers, params=params, verify=verify, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def action1():
    """Patch status: trade the client ID and secret for a token, then read each organization."""
    base = os.environ.get("ACTION1_BASE_URL", "https://app.na-2.action1.com/api/3.0").rstrip("/")
    login = requests.post(
        f"{base}/oauth2/token",
        data={
            "client_id": os.environ["ACTION1_CLIENT_ID"],
            "client_secret": os.environ["ACTION1_CLIENT_SECRET"],
        },
        timeout=TIMEOUT,
    )
    login.raise_for_status()
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    endpoints = []
    for org in get_json(f"{base}/organizations", headers)["items"]:
        url = f"{base}/endpoints/managed/{org['id']}"
        endpoints += get_json(url, headers, params={"fields": "*"})["items"]
    return endpoints


def cloudflare():
    """Devices enrolled in Zero Trust."""
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    headers = {"Authorization": f"Bearer {os.environ['CLOUDFLARE_API_TOKEN']}"}
    return get_json(f"{CLOUDFLARE_URL}/accounts/{account}/devices/physical-devices", headers)["result"]


def nessus():
    """
    The newest result for each host, across all completed scans. Reading only the
    newest scan would miss hosts that were scanned separately.
    """
    base = os.environ["NESSUS_HOST"].rstrip("/")
    keys = f"accessKey={os.environ['NESSUS_ACCESS_KEY']}; secretKey={os.environ['NESSUS_SECRET_KEY']};"
    headers = {"X-ApiKeys": keys}

    scans = get_json(f"{base}/scans", headers, verify=False)["scans"] or []
    completed = [scan for scan in scans if scan.get("status") == "completed"]
    if not completed:
        raise RuntimeError("no completed Nessus scans found")
    completed.sort(key=lambda scan: scan.get("last_modification_date", 0), reverse=True)

    newest = {}
    for scan in completed:  # newest scan first, so the first result for a host wins
        details = get_json(f"{base}/scans/{scan['id']}", headers, verify=False)
        for host in details.get("hosts") or []:
            if host.get("hostname") in newest:
                continue  # a newer scan already covered this host
            # The host's own page names each finding. judge.py still uses only the
            # counts; the names are saved in raw_nessus.json as evidence.
            url = f"{base}/scans/{scan['id']}/hosts/{host['host_id']}"
            findings = get_json(url, headers, verify=False).get("vulnerabilities") or []
            newest[host.get("hostname")] = dict(
                host,
                scan_name=scan.get("name"),
                scan_time=scan.get("last_modification_date"),
                vulnerabilities=findings,
            )
    return list(newest.values())


def wazuh():
    """Each agent's record, security configuration score, and last file-integrity scan."""
    base = os.environ.get("WAZUH_API_URL", "https://192.168.56.56:55000").rstrip("/")
    login = requests.post(
        f"{base}/security/user/authenticate",
        params={"raw": "true"},
        auth=(os.environ.get("WAZUH_API_USER", "ccm_readonly"), os.environ["WAZUH_API_PASSWORD"]),
        verify=False,
        timeout=TIMEOUT,
    )
    login.raise_for_status()
    headers = {"Authorization": f"Bearer {login.text.strip().strip(chr(34))}"}  # chr(34) is "

    agents = get_json(f"{base}/agents", headers, {"limit": 500}, verify=False)["data"]["affected_items"]
    records = []
    for agent in agents:
        record = {"agent": agent, "sca": [], "syscheck": [], "errors": []}
        paths = {"sca": f"/sca/{agent['id']}", "syscheck": f"/syscheck/{agent['id']}/last_scan"}
        for field, path in paths.items():
            try:
                record[field] = get_json(base + path, headers, verify=False)["data"]["affected_items"]
            except (requests.RequestException, KeyError, ValueError) as error:
                record["errors"].append(f"{field} request failed ({type(error).__name__})")
        records.append(record)
    return records
