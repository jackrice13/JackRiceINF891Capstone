"""
main.py - the CCM tool. Run it with:  python main.py!

    1. Collect   pull data from each tool and save the raw replies
    2. Judge     give every machine a verdict from every tool
    3. Compare   find what changed since the saved baseline
    4. Report    write the CSV files and print the results
"""

import csv
import json
import os
from datetime import datetime, timezone

import collect
import config
import judge

TOOLS = {"action1": "Action1", "cloudflare": "Cloudflare", "nessus": "Nessus", "wazuh": "Wazuh"}

# What the baseline comparison watches, and what counts as worse:
#   "up"    a higher number is worse
#   "down"  a lower number is worse
#   text    this value is healthy, and any other value is worse
# Nessus "info" is left out because it moves with plugin updates.
WATCHED = {
    "action1": {"critical_updates_missing": "up", "other_updates_missing": "up",
                "critical_vulnerabilities": "up", "other_vulnerabilities": "up",
                "reboot_required": "No", "agent_status": "Connected"},
    "cloudflare": {"active_registrations": "down"},
    "nessus": {"critical": "up", "high": "up", "medium": "up", "low": "up"},
    "wazuh": {"sca_fail": "up", "agent_status": "active"},
}

VERDICT_RANK = {"PASS": 0, "WARN": 1, "FAIL": 2, "UNKNOWN": 3, "NOT_FOUND": 3}


# --- 1. Collect -------------------------------------------------------------


def collect_all(folder):
    """Returns (data for each tool, error for each tool that failed)."""
    data, failed = {}, {}
    for tool, label in TOOLS.items():
        print(f"Pulling {label} data...")
        try:
            data[tool] = getattr(collect, tool)()  # for example, collect.nessus()
        except Exception as error:
            print(f"  {label} FAILED: {error}")
            failed[tool] = str(error)
            continue
        with open(os.path.join(folder, f"raw_{tool}.json"), "w", encoding="utf-8") as file:
            json.dump(data[tool], file, indent=2, default=str)
        print(f"  Got {len(data[tool])} record(s).")
    return data, failed


# --- 2. Judge ---------------------------------------------------------------


def same_name(value, wanted):
    return bool(value and wanted) and str(value).lower() == str(wanted).lower()


def find_record(tool, records, endpoint):
    """Finds this endpoint's record in one tool's data, or returns None."""
    hostname, ip = endpoint["hostname"], endpoint["ip"]

    if tool == "action1":
        return (next((r for r in records if same_name(r.get("name"), hostname)), None)
                or next((r for r in records if r.get("address") == ip), None))

    if tool == "cloudflare":
        return next((r for r in records if same_name(r.get("name"), hostname)), None)

    if tool == "nessus":
        # Nessus lists a host as it was typed into the scan: an IP or a name.
        for record in records:
            listed = str(record.get("hostname"))
            if listed == ip or same_name(listed.split(".")[0], hostname):
                return record
        return None

    for wanted in (endpoint.get("wazuh_name"), hostname):
        for record in records:
            if same_name(record["agent"].get("name"), wanted):
                return record
    return next((r for r in records if r["agent"].get("ip") == ip), None)


def judge_record(tool, record, now, endpoint_name):
    """Runs the tool's rules. Data in an unexpected shape becomes UNKNOWN, never PASS."""
    try:
        if tool == "action1":
            allowance = config.ACTION1_TOLERATED_OTHER_UPDATES.get(endpoint_name, 0)
            return judge.action1(record, now, allowance)
        return getattr(judge, tool)(record, now)
    except (AttributeError, KeyError, TypeError, ValueError) as error:
        return judge.result("UNKNOWN", [f"could not read this record ({error!r})"], {})


def judge_all(data, failed, now):
    """Returns {tool: [one row per endpoint]}."""
    rows = {tool: [] for tool in TOOLS}
    for endpoint in config.ENDPOINTS:
        name = endpoint["name"]
        for tool, label in TOOLS.items():
            record = find_record(tool, data.get(tool, []), endpoint)
            gap = config.EXPECTED_GAPS.get((name, tool))
            if record is not None:
                verdict = judge_record(tool, record, now, name)
            elif gap:
                verdict = judge.result("N/A", [gap], {})
            elif tool in failed:
                verdict = judge.result("UNKNOWN", [f"{label} could not be reached this run"], {})
            else:
                verdict = judge.result("NOT_FOUND", [f"{label} has no record of this endpoint"], {})
            rows[tool].append({"endpoint": name, "ip": endpoint["ip"],
                               "nist_csf": config.NIST_CSF[tool], **verdict})
    return rows


# --- 3. Compare -------------------------------------------------------------


def read_baseline(folder):
    """Reads ccm_<tool>.csv from a saved run into {(endpoint, tool): row}."""
    rows = {}
    for tool in TOOLS:
        path = os.path.join(folder, f"ccm_{tool}.csv")
        if os.path.exists(path):
            with open(path, newline="", encoding="utf-8", errors="replace") as file:
                for row in csv.DictReader(file):
                    rows[(row["endpoint"], tool)] = row
    return rows


def direction_of_change(tool, endpoint, column, rule, before, after):
    """Returns 'worse', 'better', 'changed', or None if there is no real change."""
    if rule not in ("up", "down"):  # a text measurement
        if before.lower() == after.lower():
            return None
        if before.lower() == rule.lower():
            return "worse"
        return "better" if after.lower() == rule.lower() else "changed"

    try:
        before_n, after_n = int(before), int(after)
    except ValueError:
        return None
    if tool == "action1" and column == "other_updates_missing":
        allowance = config.ACTION1_TOLERATED_OTHER_UPDATES.get(endpoint, 0)
        before_n, after_n = max(0, before_n - allowance), max(0, after_n - allowance)

    worse_by = after_n - before_n if rule == "up" else before_n - after_n
    limit = config.CHANGE_TOLERANCE.get(f"{tool}.{column}", 0)
    if worse_by > limit:
        return "worse"
    return "better" if worse_by < -limit else None


def compare(baseline, rows):
    """Returns one dictionary per change since the baseline."""
    changes = []

    def add(row, tool, field, before, after, direction):
        changes.append({"endpoint": row["endpoint"], "tool": TOOLS[tool], "field": field,
                        "baseline": before, "current": after, "direction": direction})

    for tool, tool_rows in rows.items():
        for row in tool_rows:
            old = baseline.get((row["endpoint"], tool))
            if old is None or "N/A" in (old["status"], row["status"]):
                continue

            before, after = old["status"], row["status"]
            if before != after:
                then_rank, now_rank = VERDICT_RANK.get(before), VERDICT_RANK.get(after)
                direction = "changed"
                if then_rank is not None and now_rank is not None and then_rank != now_rank:
                    direction = "worse" if now_rank > then_rank else "better"
                add(row, tool, "verdict", before, after, direction)

            for column, rule in WATCHED[tool].items():
                before = str(old.get(column) or "").strip()
                after = str("" if row.get(column) is None else row.get(column)).strip()
                if before and after:  # blank on either side means it was not measured
                    direction = direction_of_change(tool, row["endpoint"], column, rule, before, after)
                    if direction:
                        add(row, tool, column, before, after, direction)
    return changes


# --- 4. Report --------------------------------------------------------------


def write_csv(path, columns, rows):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns, restval="")
        writer.writeheader()
        writer.writerows(rows)


def report(folder, rows, changes):
    verdict = {(row["endpoint"], tool): row["status"] for tool, table in rows.items() for row in table}
    matrix = [{"endpoint": e["name"], **{label: verdict[(e["name"], tool)] for tool, label in TOOLS.items()}}
              for e in config.ENDPOINTS]
    write_csv(os.path.join(folder, "ccm_matrix.csv"), ["endpoint", *TOOLS.values()], matrix)

    for tool, table in rows.items():
        columns = (["endpoint", "ip", "nist_csf", "status"] + judge.COLUMNS[tool]
                   + ["last_seen_utc", "minutes_since_seen", "stale", "notes"])
        write_csv(os.path.join(folder, f"ccm_{tool}.csv"), columns, table)

    print(f"\n{'Endpoint':<22}" + "".join(f"{label:<12}" for label in TOOLS.values()))
    for line in matrix:
        print("".join(f"{value:<12}" if key != "endpoint" else f"{value:<22}" for key, value in line.items()))

    if changes is None:
        print(f"\nBaseline folder '{config.BASELINE_FOLDER}' was not found, so no comparison was made.")
    else:
        write_csv(os.path.join(folder, "ccm_changes.csv"),
                  ["endpoint", "tool", "field", "baseline", "current", "direction"], changes)
        print(f"\nChanges since baseline ({len(changes)}):")
        order = {"worse": 0, "changed": 1, "better": 2}
        for c in sorted(changes, key=lambda c: (order[c["direction"]], c["endpoint"], c["tool"])):
            print(f"  {c['endpoint']:<22}{c['tool']:<12}{c['direction']:<9}"
                  f"{c['field']}: {c['baseline']} -> {c['current']}")

    print(f"\nDone. Files are in ./{folder}/")


def main():
    now = datetime.now(timezone.utc)
    folder = f"ccm_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(folder, exist_ok=True)

    data, failed = collect_all(folder)
    rows = judge_all(data, failed, now)

    changes = None
    if os.path.isdir(config.BASELINE_FOLDER):
        changes = compare(read_baseline(config.BASELINE_FOLDER), rows)

    report(folder, rows, changes)


if __name__ == "__main__":
    main()
