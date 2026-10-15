from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable


EMPTY_MARKERS = {"", "-", "N/A", "Unknown", "None"}
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
SEVERITY_WEIGHTS = {
    "Critical": 100,
    "High": 80,
    "Medium": 50,
    "Low": 20,
    "Informational": 5,
}


def _valid(value: Any) -> bool:
    return str(value or "").strip() not in EMPTY_MARKERS


def _text(value: Any, default: str = "Unknown") -> str:
    text = str(value or "").strip()
    return text or default


def _severity(value: Any) -> str:
    text = str(value or "").strip().replace("_", " ").lower()
    aliases = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "information": "Informational",
        "info": "Informational",
    }
    return aliases.get(text, "Unknown")


def count_by(records: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    counter = Counter(str(row.get(field) or "").strip() for row in records)
    counter.pop("", None)
    return [{field: key, "Count": value} for key, value in counter.most_common()]


def top_by(records: list[dict[str, Any]], field: str, top_n: int) -> list[dict[str, Any]]:
    return count_by(records, field)[:top_n]


def severity_distribution(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter = Counter(_severity(row.get("Severity Name")) for row in records)
    rows = [
        {
            "Severity Name": severity,
            "Detection Count": int(counter.get(severity, 0)),
            "Severity Weight": SEVERITY_WEIGHTS[severity],
        }
        for severity in SEVERITY_ORDER
    ]
    if counter.get("Unknown"):
        rows.append(
            {
                "Severity Name": "Unknown",
                "Detection Count": int(counter["Unknown"]),
                "Severity Weight": 0,
            }
        )
    return rows


def _severity_score(counts: dict[str, int], total: int) -> tuple[int, int]:
    raw = sum(int(counts.get(severity, 0)) * weight for severity, weight in SEVERITY_WEIGHTS.items())
    # Mirrors the YAML formula: (Raw_Severity_Point / (Total_Detection * 100)) * 100.
    score = round(raw / total) if total else 0
    return raw, int(score)


def _standard_priority(counts: dict[str, int], total: int) -> str:
    if counts.get("Critical", 0) > 0 or counts.get("High", 0) > 0:
        return "Take Care"
    if counts.get("Medium", 0) > 0:
        return "Review"
    if total >= 100 and counts.get("Informational", 0) > 0:
        return "Monitor / Noise Review"
    return "Monitor"


def _repetition_priority(counts: dict[str, int], repetition_ratio: float) -> str:
    if counts.get("Critical", 0) > 0 or counts.get("High", 0) > 0:
        return "Take Care"
    if counts.get("Medium", 0) > 0:
        return "Review"
    if repetition_ratio >= 20:
        return "Monitor / Noise Review"
    return "Monitor"


def _risk_sort(counts: dict[str, int], tail_value: int) -> int:
    return (
        int(counts.get("Critical", 0)) * 10000
        + int(counts.get("High", 0)) * 1000
        + int(counts.get("Medium", 0)) * 100
        + int(tail_value)
    )


def _severity_breakdown(
    records: Iterable[dict[str, Any]],
    group_fields: list[str],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], dict[str, int]] = {}
    totals: Counter[tuple[str, ...]] = Counter()

    for row in records:
        key = tuple(_text(row.get(field)) for field in group_fields)
        if key not in grouped:
            grouped[key] = {severity: 0 for severity in SEVERITY_ORDER}
        severity = _severity(row.get("Severity Name"))
        if severity in SEVERITY_WEIGHTS:
            grouped[key][severity] += 1
        totals[key] += 1

    output: list[dict[str, Any]] = []
    for key, counts in grouped.items():
        total = int(totals[key])
        raw, score = _severity_score(counts, total)
        item = {field: key[idx] for idx, field in enumerate(group_fields)}
        item.update(
            {
                "Total Detection": total,
                **{severity: int(counts[severity]) for severity in SEVERITY_ORDER},
                "Raw Severity Point": raw,
                "Severity Priority Score": score,
                "Priority": _standard_priority(counts, total),
                "Risk Sort": _risk_sort(counts, total),
            }
        )
        output.append(item)

    return sorted(
        output,
        key=lambda item: (int(item.get("Risk Sort", 0)), int(item.get("Total Detection", 0))),
        reverse=True,
    )


def tactic_technique_by_severity(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _severity_breakdown(records, ["Tactic", "Technique"])


def host_requiring_attention(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _severity_breakdown(records, ["Hostname"])


def _unique_rollup(
    records: list[dict[str, Any]],
    *,
    base_fields: list[str],
    result_fields: list[str],
) -> list[dict[str, Any]]:
    # First group mirrors the YAML's first groupBy(..., function=count(as=Repeat_Count)).
    repeated: Counter[tuple[str, ...]] = Counter()
    for row in records:
        parts: list[str] = []
        for field in base_fields:
            if field == "Severity Name":
                parts.append(_severity(row.get(field)))
            else:
                parts.append(_text(row.get(field)))
        repeated[tuple(parts)] += 1

    # Second group mirrors the YAML's second groupBy, including severity-weighted repeat counts.
    aggregated: dict[tuple[str, ...], dict[str, Any]] = {}
    base_positions = {field: idx for idx, field in enumerate(base_fields)}
    severity_pos = base_positions["Severity Name"]

    for base_key, repeat_count in repeated.items():
        result_key = tuple(base_key[base_positions[field]] for field in result_fields)
        item = aggregated.setdefault(
            result_key,
            {
                "Unique Detection": 0,
                "Total Detection": 0,
                **{severity: 0 for severity in SEVERITY_ORDER},
            },
        )
        item["Unique Detection"] += 1
        item["Total Detection"] += int(repeat_count)
        severity = base_key[severity_pos]
        if severity in SEVERITY_WEIGHTS:
            item[severity] += int(repeat_count)

    output: list[dict[str, Any]] = []
    for result_key, item in aggregated.items():
        unique_count = int(item["Unique Detection"])
        total = int(item["Total Detection"])
        ratio = round(total / unique_count, 2) if unique_count else 0.0
        counts = {severity: int(item[severity]) for severity in SEVERITY_ORDER}
        raw, score = _severity_score(counts, total)
        row = {field: result_key[idx] for idx, field in enumerate(result_fields)}
        row.update(
            {
                "Unique Detection": unique_count,
                "Total Detection": total,
                "Repetition Ratio": ratio,
                **counts,
                "Raw Severity Point": raw,
                "Severity Priority Score": score,
                "Priority": _repetition_priority(counts, ratio),
                "Risk Sort": _risk_sort(counts, unique_count),
            }
        )
        output.append(row)

    return sorted(
        output,
        key=lambda row: (int(row.get("Risk Sort", 0)), int(row.get("Unique Detection", 0))),
        reverse=True,
    )


def unique_detection_per_host(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _unique_rollup(
        records,
        base_fields=["Hostname", "Severity Name", "Tactic", "Technique"],
        result_fields=["Hostname"],
    )


def unique_tactic_technique_by_severity(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _unique_rollup(
        records,
        base_fields=["Tactic", "Technique", "Severity Name", "Hostname"],
        result_fields=["Tactic", "Technique"],
    )


def critical_investigation(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    columns = [
        "Created Timestamp",
        "Hostname",
        "Username",
        "Severity Name",
        "Tactic",
        "Technique",
        "Objective",
        "Detection Name",
        "Description",
        "File Name",
        "Command Line",
        "SHA256",
        "Agent ID",
    ]
    rows: list[dict[str, Any]] = []
    for record in records:
        if _severity(record.get("Severity Name")) != "Critical":
            continue
        rows.append({column: record.get(column, "") for column in columns})
    rows.sort(key=lambda row: str(row.get("Created Timestamp") or ""), reverse=True)
    return rows


def daily_trend(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for row in records:
        value = str(row.get("Created Timestamp") or "").strip()
        if not value:
            continue
        try:
            day = datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
        except ValueError:
            day = value[:10]
        counter[day] += 1
    return [{"Date": key, "Count": counter[key]} for key in sorted(counter)]


def field_coverage(records: list[dict[str, Any]], fields: list[str]) -> list[dict[str, Any]]:
    total = len(records)
    output = []
    for field in fields:
        available = sum(1 for row in records if _valid(row.get(field)))
        output.append(
            {
                "Field": field,
                "Available": available,
                "Missing": total - available,
                "Coverage %": round((available / total * 100), 2) if total else 0.0,
            }
        )
    return output


def build_analytics(records: list[dict[str, Any]], top_n: int = 10) -> dict[str, Any]:
    status = count_by(records, "Status")
    severity = severity_distribution(records)
    closed = sum(item["Count"] for item in status if str(item["Status"]).lower() in {"closed", "resolved"})
    new = sum(item["Count"] for item in status if str(item["Status"]).lower() in {"new", "open", "unreviewed"})
    total = len(records)

    tactic_severity = tactic_technique_by_severity(records)
    host_attention = host_requiring_attention(records)
    unique_host = unique_detection_per_host(records)
    unique_tactic = unique_tactic_technique_by_severity(records)
    critical = critical_investigation(records)

    return {
        "total": total,
        "closed": closed,
        "new": new,
        "closure_rate_pct": round(closed / total * 100, 2) if total else None,
        "backlog_pct": round(new / total * 100, 2) if total else None,
        "status": status,
        "severity": severity,
        "tactic_technique_by_severity": tactic_severity,
        "host_requiring_attention": host_attention,
        "unique_detection_per_host": unique_host,
        "unique_tactic_technique_by_severity": unique_tactic,
        "critical_investigation": critical,
        "take_care_hosts": sum(1 for row in host_attention if row.get("Priority") == "Take Care"),
        "review_hosts": sum(1 for row in host_attention if row.get("Priority") == "Review"),
        "critical_count": sum(1 for row in records if _severity(row.get("Severity Name")) == "Critical"),
        "high_count": sum(1 for row in records if _severity(row.get("Severity Name")) == "High"),
        "medium_count": sum(1 for row in records if _severity(row.get("Severity Name")) == "Medium"),
        # Legacy quantitative views retained for backward compatibility.
        "top_hosts": top_by(records, "Hostname", top_n),
        "top_tactics": top_by(records, "Tactic", top_n),
        "top_techniques": top_by(records, "Technique", top_n),
        "top_files": top_by(records, "File Name", top_n),
        "top_hashes": top_by(records, "SHA256", top_n),
        "top_command_lines": top_by(records, "Command Line", top_n),
        "top_users": top_by(records, "Username", top_n),
        "daily_trend": daily_trend(records),
        "field_coverage": field_coverage(
            records,
            [
                "Status",
                "Severity Name",
                "Hostname",
                "Tactic",
                "Technique",
                "Detection Name",
                "File Name",
                "SHA256",
                "Command Line",
                "Username",
            ],
        ),
    }
