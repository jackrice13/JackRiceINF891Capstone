"""
judge.py - the PASS / WARN / FAIL rules. This is the file to cite in your methodology.!

There is one function per tool. Each one lists its FAIL reasons and WARN reasons,
then finish() turns those lists into the verdict:
    any FAIL reason  -> FAIL
    any WARN reason  -> WARN
    neither          -> PASS

UNKNOWN means the data needed for a verdict was missing. It never becomes a PASS.
Nothing in this file touches the network.
"""

import re
from datetime import datetime, timezone

import config

# The measurement columns in each tool's CSV file.
COLUMNS = {
    "action1": ["critical_updates_missing", "other_updates_missing", "critical_vulnerabilities",
                "other_vulnerabilities", "reboot_required", "agent_status", "action1_update_status"],
    "cloudflare": ["active_registrations", "warp_client_version", "device_type", "os_version"],
    "nessus": ["critical", "high", "medium", "low", "info", "scan_name"],
    "wazuh": ["agent_name", "os", "agent_status", "agent_version", "sca_policy", "sca_score", "sca_pass",
              "sca_fail", "sca_invalid", "sca_last_scan", "fim_last_scan_end"],
}


def parse_time(value):
    """
    Reads any of the tools' time formats into a UTC time, or None if unreadable.
      Nessus:           1760000000 (seconds since 1970)
      Action1:          "2026-10-12_19-47-05"
      Cloudflare/Wazuh: "2026-10-12T19:50:25.910341Z"
    """
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if "_" in value:
            parsed = datetime.strptime(value, "%Y-%m-%d_%H-%M-%S")
        else:
            cleaned = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
            parsed = datetime.fromisoformat(cleaned)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def time_text(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else ""


def minutes_since(moment, now):
    return round((now - moment).total_seconds() / 60)


def number(mapping, key):
    """Reads a count from a dictionary. None means 'not reported', which is not zero."""
    value = mapping.get(key) if isinstance(mapping, dict) else None
    is_number = isinstance(value, (int, float)) and not isinstance(value, bool)
    return int(value) if is_number else None


def result(status, notes, details, last_seen=None, age="", stale=""):
    return {
        "status": status,
        "notes": "; ".join(notes),
        "last_seen_utc": time_text(last_seen),
        "minutes_since_seen": age,
        "stale": stale,
        **details,
    }


def finish(tool, now, last_seen, fails, warns, details, info=()):
    """Adds the data-age check, then chooses the verdict from the reason lists."""
    limit = config.STALE_AFTER_MINUTES[tool]
    age, stale = "", ""
    if last_seen is None:
        warns.append("last-seen time unavailable")
    else:
        age = minutes_since(last_seen, now)
        stale = "yes" if age > limit else "no"
        if age > limit:
            warns.append(f"stale: {age} min old (limit {limit})")

    status = "FAIL" if fails else "WARN" if warns else "PASS"
    return result(status, fails + warns + list(info), details, last_seen, age, stale)


def action1(record, now, tolerated_updates=0):
    updates, vulns = record.get("missing_updates"), record.get("vulnerabilities")
    critical_updates, other_updates = number(updates, "critical"), number(updates, "other")
    critical_vulns, other_vulns = number(vulns, "critical"), number(vulns, "other")
    reboot, connection = record.get("reboot_required"), record.get("status")
    details = {
        "critical_updates_missing": critical_updates,
        "other_updates_missing": other_updates,
        "critical_vulnerabilities": critical_vulns,
        "other_vulnerabilities": other_vulns,
        "reboot_required": reboot,
        "agent_status": connection,
        "action1_update_status": record.get("update_status"),
    }
    last_seen = parse_time(record.get("last_seen"))
    if critical_updates is None and critical_vulns is None:
        return result("UNKNOWN", ["no update or vulnerability data reported"], details, last_seen)

    fails, warns, info = [], [], []
    if (critical_updates or 0) > 0:
        fails.append("critical updates missing")
    if (critical_vulns or 0) > 0:
        fails.append("critical vulnerabilities present")

    # The allowance changes the verdict only. The CSV still shows the real count.
    counted_updates = max(0, (other_updates or 0) - tolerated_updates)
    if counted_updates > 0:
        warns.append("non-critical updates missing")
    if counted_updates < (other_updates or 0):
        info.append("known recurring update tolerated (see config.py)")
    if (other_vulns or 0) > 0:
        warns.append("non-critical vulnerabilities present")
    if reboot == "Yes":
        warns.append("reboot pending")
    if connection is not None and connection != "Connected":
        warns.append(f"agent not connected ({connection})")

    return finish("action1", now, last_seen, fails, warns, details, info)


def cloudflare(record, now):
    registrations = record.get("active_registrations")
    details = {
        "active_registrations": registrations,
        "warp_client_version": record.get("client_version"),
        "device_type": record.get("device_type"),
        "os_version": record.get("os_version"),
    }
    last_seen = parse_time(record.get("last_seen_at"))
    if not isinstance(registrations, int) or isinstance(registrations, bool):
        return result("UNKNOWN", ["registration count not reported"], details, last_seen)

    fails = [] if registrations >= 1 else ["no active registration"]
    return finish("cloudflare", now, last_seen, fails, [], details)


def nessus_counts(host):
    """Reads severity counts from either shape Nessus uses, or returns None."""
    names = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
    if any(name in host for name in names.values()):
        return {name: int(host.get(name) or 0) for name in names.values()}

    items = (host.get("severitycount") or {}).get("item")
    if isinstance(items, dict):  # a single entry can arrive on its own
        items = [items]
    if not items:
        return None
    counts = {name: 0 for name in names.values()}
    for item in items:
        counts[names[int(item["severitylevel"])]] += int(item.get("count") or 0)
    return counts


def nessus(host, now):
    last_seen = parse_time(host.get("scan_time"))
    counts = nessus_counts(host)
    details = {"scan_name": host.get("scan_name"), **(counts or {})}
    if counts is None:
        return result("UNKNOWN", ["could not read severity counts"], details, last_seen)

    fails = ["critical or high findings present"] if counts["critical"] or counts["high"] else []
    warns = ["medium findings present"] if counts["medium"] else []
    return finish("nessus", now, last_seen, fails, warns, details)


def wazuh(record, now):
    agent = record.get("agent") or {}
    connection = agent.get("status")
    system = agent.get("os") or {}
    details = {
        "agent_name": agent.get("name"),
        "os": " ".join(str(system[key]) for key in ("name", "version") if system.get(key)),
        "agent_status": connection,
        "agent_version": agent.get("version"),
    }
    last_seen = parse_time(agent.get("lastKeepAlive"))
    if connection is None:
        return result("UNKNOWN", ["no agent status reported"], details, last_seen)

    fails, warns, info = [], [], []
    scan_limit = config.WAZUH_SCAN_STALE_MINUTES
    if connection != "active":
        fails.append(f"agent not active ({connection}), so this machine is not being monitored")

    # Security configuration score. With several policies, the weakest one is judged.
    policies = record.get("sca") or []
    scored = [policy for policy in policies if number(policy, "score") is not None]
    if policies:
        weakest = min(scored or policies, key=lambda policy: number(policy, "score") or 0)
        score = number(weakest, "score")
        sca_end = parse_time(weakest.get("end_scan"))
        details.update({
            "sca_policy": weakest.get("name"),
            "sca_score": score,
            "sca_pass": number(weakest, "pass"),
            "sca_fail": number(weakest, "fail"),
            "sca_invalid": number(weakest, "invalid"),
            "sca_last_scan": time_text(sca_end),
        })
        if score is None:
            warns.append("SCA score not reported")
        elif score < config.SCA_FAIL_BELOW:
            fails.append(f"SCA score {score}% is below {config.SCA_FAIL_BELOW}%")
        elif score < config.SCA_WARN_BELOW:
            warns.append(f"SCA score {score}% is below {config.SCA_WARN_BELOW}%")
        if sca_end and minutes_since(sca_end, now) > scan_limit:
            warns.append(f"SCA scan is older than {scan_limit} min")
    else:
        warns.append("no security configuration (SCA) results")

    # File-integrity monitoring. No end time means a scan may still be running.
    scans = record.get("syscheck") or []
    if not scans:
        warns.append("no file integrity scan reported")
    else:
        fim_end = parse_time(scans[0].get("end"))
        details["fim_last_scan_end"] = time_text(fim_end)
        if fim_end is None:
            info.append("file integrity scan has not finished")
        elif minutes_since(fim_end, now) > scan_limit:
            warns.append(f"file integrity scan is older than {scan_limit} min")

    # A failed request says nothing about the machine, so it cannot support a PASS
    # or WARN. A FAIL found from the data that did arrive still stands.
    errors = record.get("errors") or []
    if errors and not fails:
        return result("UNKNOWN", errors, details, last_seen)

    return finish("wazuh", now, last_seen, fails, warns, details, info + errors)
