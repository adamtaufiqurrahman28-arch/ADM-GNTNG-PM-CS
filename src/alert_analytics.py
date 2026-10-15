from __future__ import annotations

from typing import Any

import pandas as pd

from detector.analytics import build_analytics


def count_table(df: pd.DataFrame, column: str, top_n: int | None = None) -> pd.DataFrame:
    if df is None or df.empty or column not in df.columns:
        return pd.DataFrame(columns=[column, "Count", "Percentage"])
    values = df[column].fillna("Unknown").replace("", "Unknown").astype(str)
    counts = values.value_counts(dropna=False)
    if top_n:
        counts = counts.head(top_n)
    result = counts.rename_axis(column).reset_index(name="Count")
    total = len(df)
    result["Percentage"] = (result["Count"] / total * 100).round(2) if total else 0
    return result


def alert_tables(alerts: pd.DataFrame, top_n: int = 10) -> dict[str, pd.DataFrame]:
    if alerts is None:
        alerts = pd.DataFrame()
    records = alerts.where(pd.notna(alerts), None).to_dict(orient="records") if not alerts.empty else []
    analytics = build_analytics(records, top_n=top_n)

    tables = {
        "By Status": pd.DataFrame(analytics["status"]),
        "By Severity": pd.DataFrame(analytics["severity"]),
        "Tactic & Technique by Severity": pd.DataFrame(analytics["tactic_technique_by_severity"]),
        "Host Requiring Attention": pd.DataFrame(analytics["host_requiring_attention"]),
        "Unique Detection per Host": pd.DataFrame(analytics["unique_detection_per_host"]),
        "Unique Tactic & Technique by Severity": pd.DataFrame(analytics["unique_tactic_technique_by_severity"]),
        "Critical Detection Investigation": pd.DataFrame(analytics["critical_investigation"]),
        # Legacy views remain available for users who still want raw frequency rankings.
        "Top Tactic": pd.DataFrame(analytics["top_tactics"]),
        "Top Technique": pd.DataFrame(analytics["top_techniques"]),
        "Top Host": pd.DataFrame(analytics["top_hosts"]),
        "Top User": pd.DataFrame(analytics["top_users"]),
        "Top File": pd.DataFrame(analytics["top_files"]),
        "Top Hash": pd.DataFrame(analytics["top_hashes"]),
        "Top Command Line": pd.DataFrame(analytics["top_command_lines"]),
        "By Platform": count_table(alerts, "Platform"),
        "By Product": count_table(alerts, "Product"),
        "By Detection Type": count_table(alerts, "Detection Type"),
    }

    if not alerts.empty and "Created Timestamp" in alerts.columns:
        created = pd.to_datetime(alerts["Created Timestamp"], utc=True, errors="coerce")
        daily = created.dt.date.value_counts().sort_index().rename_axis("Date").reset_index(name="Count")
    else:
        daily = pd.DataFrame(columns=["Date", "Count"])
    tables["Daily Trend"] = daily

    coverage_rows: list[dict[str, Any]] = []
    for column in alerts.columns:
        populated = alerts[column].notna() & alerts[column].astype(str).ne("")
        coverage_rows.append(
            {
                "Field": column,
                "Populated": int(populated.sum()),
                "Missing": int((~populated).sum()),
                "Coverage %": round(float(populated.mean() * 100), 2) if len(alerts) else 0,
            }
        )
    tables["Field Coverage"] = pd.DataFrame(coverage_rows)
    return tables


def alert_summary(alerts: pd.DataFrame, metadata: dict[str, Any]) -> pd.DataFrame:
    total = len(alerts) if alerts is not None else 0
    records = alerts.where(pd.notna(alerts), None).to_dict(orient="records") if total else []
    analytics = build_analytics(records, top_n=10)

    status = alerts["Status"].fillna("Unknown").astype(str).str.lower() if total and "Status" in alerts.columns else pd.Series(dtype=str)
    closed = int(status.isin(["closed", "resolved"]).sum())
    new = int(status.isin(["new", "open", "unreviewed"]).sum())
    in_progress = int(status.isin(["in progress", "in_progress", "investigating"]).sum())
    reopened = int(status.eq("reopened").sum())
    backlog = new + in_progress + reopened
    rows = [
        ["Total Alert", total],
        ["Critical", analytics["critical_count"]],
        ["High", analytics["high_count"]],
        ["Medium", analytics["medium_count"]],
        ["Host — Take Care", analytics["take_care_hosts"]],
        ["Host — Review", analytics["review_hosts"]],
        ["New / Open", new],
        ["In Progress", in_progress],
        ["Reopened", reopened],
        ["Closed / Resolved", closed],
        ["Closure Rate %", round(closed / total * 100, 4) if total else None],
        ["Backlog Rate %", round(backlog / total * 100, 4) if total else None],
        ["Collection Pages", metadata.get("collection_pages")],
        ["Truncated", metadata.get("truncated")],
        ["Collection Mode", metadata.get("mode")],
        ["UTC Start", metadata.get("start_utc")],
        ["UTC End Exclusive", metadata.get("end_exclusive_utc")],
        ["Page Size", metadata.get("page_size")],
        ["Max Records", metadata.get("max_records")],
    ]
    return pd.DataFrame(rows, columns=["Metric", "Value"])
