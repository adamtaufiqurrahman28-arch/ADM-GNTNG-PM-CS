from __future__ import annotations

import json
from datetime import date
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pandas as pd

from src.alert_analytics import alert_summary, alert_tables
from src.excel_exporter import (
    build_alert_workbook,
    build_host_sensor_workbook,
    build_policy_workbook,
)
from src.falcon_collectors import build_alert_date_filter
from src.normalizers import normalize_alerts, normalize_hosts, normalize_policies
from src.policy_assessment import assess_settings, load_baseline, policy_summary
from src.policy_mapping import disabled_items_summary, load_label_mapping, policy_matrix_dataframe
from src.sensor_health import classify_sensor_health, normalize_sensor_matrix, sensor_health_summary


DATA = Path(__file__).parents[1] / "data"


def workbook_sheet_names(content: bytes) -> list[str]:
    import xml.etree.ElementTree as ET

    with ZipFile(BytesIO(content)) as archive:
        root = ET.fromstring(archive.read("xl/workbook.xml"))
    ns = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    return [sheet.attrib["name"] for sheet in root.find("a:sheets", ns)]


def test_host_and_sensor_health_single_lampiran() -> None:
    host_records = pd.read_csv(DATA / "sample_hosts.csv").to_dict(orient="records")
    hosts, raw = normalize_hosts(host_records)
    matrix = normalize_sensor_matrix(pd.read_csv(DATA / "sample_sensor_matrix.csv"))
    assessment = classify_sensor_health(
        hosts,
        matrix,
        date.today(),
        missing_version_policy="Unsupported",
    )
    assert len(hosts) == 15
    assert len(raw) == 15
    assert "Support Status" in assessment.columns
    assert len(sensor_health_summary(assessment)) == 3
    assert {"Host ID", "CID", "Content Update Policy", "USB Device Policy", "Host Retention Policy"}.issubset(hosts.columns)

    workbook = build_host_sensor_workbook(
        assessment,
        matrix,
        {"collector": "test", "source": "Hosts API"},
        {"assessment_date": date.today().isoformat(), "missing_version_policy": "Unsupported"},
        customer_name="PT Demo",
    )
    assert workbook[:2] == b"PK"
    assert workbook_sheet_names(workbook) == [
        "Ringkasan",
        "All Hosts",
        "Unsupported",
        "RFM",
        "RFM Unknown",
        "Inactive >14 Hari",
        "Version Distribution",
        "Sensor Matrix",
        "Data Quality",
    ]


def test_policy_extraction_and_matrix_export() -> None:
    policies = json.loads((DATA / "sample_policies.json").read_text())
    members = json.loads((DATA / "sample_policy_members.json").read_text())
    mapping = load_label_mapping(DATA / "policy_setting_labels.csv")
    groups, member_df, settings, raw = normalize_policies(policies, members, mapping)
    baseline = load_baseline(pd.read_csv(DATA / "policy_baseline_template.csv"))
    assessed = assess_settings(settings, baseline)
    summary = policy_summary(groups, assessed)
    assert len(groups) == 3
    assert len(member_df) == 15
    assert settings["Configuration Status"].eq("Disabled").sum() >= 1
    assert not set(settings["Display Name"].str.lower()).intersection({"type", "value", "detection", "prevention"})
    assert "Enhanced DLL Load Visibility" in settings["Display Name"].values
    assert "DET: AGGRESSIVE / PREV: MODERATE" in settings["Display Value"].values
    assert len(disabled_items_summary(assessed)) >= 1
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "Enhanced DLL Load Visibility" in matrix["Configuration Item"].values
    assert "Not Compliant" in assessed["Baseline Status"].values
    assert len(summary) == 3
    workbook = build_policy_workbook(groups, member_df, assessed, raw, {"collector": "test"})
    assert workbook[:2] == b"PK"
    names = workbook_sheet_names(workbook)
    assert names[0:2] == ["Summary", "Policy Groups"]
    assert "Windows Prevention Policy" in names
    assert "Linux Prevention Policy" in names
    assert "Mac Prevention Policy" in names
    assert "Disabled Items" in names
    assert "All Settings" in names
    assert "Unmapped Items" in names


def test_alert_normalization_and_export() -> None:
    records = pd.read_csv(DATA / "sample_alerts.csv").to_dict(orient="records")
    alerts, raw = normalize_alerts(records)
    metadata = {
        "customer_name": "PT Demo",
        "report_label": "Detection Report",
        "start_date": "2026-04-01",
        "end_date": "2026-06-30",
        "base_url": "us-1",
        "collection_pages": 1,
        "truncated": False,
        "fql_filter": "sample",
    }
    assert len(alerts) == 100
    assert not alert_summary(alerts, metadata).empty
    assert "Top Host" in alert_tables(alerts)
    workbook = build_alert_workbook(alerts, raw, metadata)
    assert workbook[:2] == b"PK"
    assert workbook_sheet_names(workbook)[0:2] == ["Summary", "Alerts Detail"]


def test_alert_filter_timezone() -> None:
    fql, start, end = build_alert_date_filter(
        date(2026, 4, 1),
        date(2026, 6, 30),
        timezone_name="Asia/Jakarta",
    )
    assert "created_timestamp" in fql
    assert start.isoformat().startswith("2026-03-31T17:00:00")
    assert end.isoformat().startswith("2026-06-30T17:00:00")


def test_alert_combined_page_limit_and_413_detection() -> None:
    from src.falcon_collectors import _is_request_too_large

    assert _is_request_too_large({
        "status_code": 400,
        "body": {"errors": [{"code": 413, "message": "request too large"}]},
    })
    assert not _is_request_too_large({
        "status_code": 400,
        "body": {"errors": [{"code": 400, "message": "invalid query filter"}]},
    })



def test_policy_nested_section_payload_yields_on_off_values() -> None:
    policies = [{
        "id": "policy-real-shape",
        "name": "Workstation Policy",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 12,
        "prevention_settings": [
            {
                "name": "Enhanced Visibility",
                "settings": [
                    {
                        "id": "DLLLoadVisibility",
                        "name": "Enhanced DLL Load Visibility",
                        "type": "toggle",
                        "value": {"enabled": False},
                    },
                    {
                        "id": "ScriptBasedExecutionMonitoring",
                        "name": "Script-Based Execution Monitoring",
                        "type": "toggle",
                        "value": {"configured": True, "enabled": True},
                    },
                ],
            },
            {
                "name": "Cloud Machine Learning",
                "settings": [
                    {
                        "id": "CloudAntiMalware",
                        "name": "Cloud Anti-malware",
                        "type": "mlslider",
                        "value": {"detection": "AGGRESSIVE", "prevention": "MODERATE"},
                    }
                ],
            },
        ],
    }]
    groups, _, settings, _ = normalize_policies(policies, [], pd.DataFrame())
    assessed = assess_settings(settings, None)
    assert set(settings["Setting ID"]) == {
        "DLLLoadVisibility",
        "ScriptBasedExecutionMonitoring",
        "CloudAntiMalware",
    }
    assert not settings["Display Value"].eq("").any()
    values = dict(zip(settings["Setting ID"], settings["Display Value"]))
    assert values["DLLLoadVisibility"] == "OFF"
    assert values["ScriptBasedExecutionMonitoring"] == "ON"
    assert values["CloudAntiMalware"] == "DET: AGGRESSIVE / PREV: MODERATE"
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "OFF" in matrix["Workstation Policy"].values
    assert "ON" in matrix["Workstation Policy"].values


def test_policy_matrix_duplicate_policy_names_are_safe_for_styler() -> None:
    policies = pd.DataFrame([
        {
            "Policy ID": "policy-aaaaaaaa11111111",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Enabled": True,
            "Member Count": 10,
            "Precedence": 1,
        },
        {
            "Policy ID": "policy-bbbbbbbb22222222",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Enabled": True,
            "Member Count": 20,
            "Precedence": 2,
        },
    ])
    settings = pd.DataFrame([
        {
            "Policy ID": "policy-aaaaaaaa11111111",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Item Key": "enhanced_dll_load_visibility",
            "Display Name": "Enhanced DLL Load Visibility",
            "Section": "Sensor Visibility",
            "Sort Order": 1,
            "Best Practice": "ON",
            "Display Value": "OFF",
            "Current Value": False,
        },
        {
            "Policy ID": "policy-bbbbbbbb22222222",
            "Policy Name": "Duplicate Policy",
            "Platform": "Windows",
            "Item Key": "enhanced_dll_load_visibility",
            "Display Name": "Enhanced DLL Load Visibility",
            "Section": "Sensor Visibility",
            "Sort Order": 1,
            "Best Practice": "ON",
            "Display Value": "ON",
            "Current Value": True,
        },
    ])

    matrix = policy_matrix_dataframe(policies, settings, "Windows")
    assert matrix.index.is_unique
    assert matrix.columns.is_unique
    duplicate_columns = [column for column in matrix.columns if str(column).startswith("Duplicate Policy") ]
    assert len(duplicate_columns) == 2
    assert duplicate_columns[0] != duplicate_columns[1]
    # This is the exact operation used by Streamlit before marshalling Styler.
    matrix.style.map(lambda value: "")._compute()


def test_policy_dynamic_api_discovery_without_static_mapping() -> None:
    """A future Falcon API setting must appear without any local mapping row."""
    policies = [{
        "id": "policy-dynamic",
        "name": "Dynamic Windows Policy",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 1,
        "prevention_settings": [
            {
                "name": "On Write",
                "settings": [
                    {
                        "id": "DetectPackageOnWrite",
                        "name": "Detect Package on Write",
                        "type": "toggle",
                        "value": {"configured": True, "enabled": True},
                    },
                    {
                        "id": "QuarantinePackageOnWrite",
                        "name": "Quarantine Package on Write",
                        "type": "toggle",
                        "value": {"configured": True, "enabled": False},
                    },
                    {
                        "id": "FutureFalconProtection2027",
                        "name": "Future Falcon Protection 2027",
                        "type": "toggle",
                        "value": {"configured": True, "enabled": True},
                    },
                ],
            }
        ],
    }]

    groups, _, settings, _ = normalize_policies(policies, [], load_label_mapping(None))
    assert set(settings["Setting ID"]) == {
        "DetectPackageOnWrite",
        "QuarantinePackageOnWrite",
        "FutureFalconProtection2027",
    }
    assert settings["Mapping Status"].eq("API native").all()
    assert settings["Display Source"].eq("Falcon API").all()
    assert settings["Section"].eq("On Write").all()

    assessed = assess_settings(settings, None)
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "Detect Package on Write" in matrix["Configuration Item"].values
    assert "Quarantine Package on Write" in matrix["Configuration Item"].values
    assert "Future Falcon Protection 2027" in matrix["Configuration Item"].values


def test_optional_mapping_is_override_not_whitelist() -> None:
    """Mapped and unmapped API settings must both remain in the matrix."""
    policies = [{
        "id": "policy-overrides",
        "name": "Override Test",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 1,
        "prevention_settings": [{
            "name": "On Write",
            "settings": [
                {"id": "DetectOnWrite", "name": "Detect on Write", "type": "toggle", "value": {"enabled": True}},
                {"id": "BrandNewSetting", "name": "Brand New Setting", "type": "toggle", "value": {"enabled": True}},
            ],
        }],
    }]
    overrides = pd.DataFrame([{
        "Platform": "Windows",
        "Item Match": "detect_on_write",
        "Display Name": "Detect on write (custom)",
        "Section": "Custom Section",
        "Sort Order": 10,
    }])
    groups, _, settings, _ = normalize_policies(policies, [], load_label_mapping(overrides))
    by_id = settings.set_index("Setting ID")
    assert by_id.loc["DetectOnWrite", "Display Name"] == "Detect on write (custom)"
    assert by_id.loc["BrandNewSetting", "Display Name"] == "Brand New Setting"
    assert by_id.loc["BrandNewSetting", "Mapping Status"] == "API native"

    matrix = policy_matrix_dataframe(groups, assess_settings(settings, None), "Windows")
    assert "Detect on write (custom)" in matrix["Configuration Item"].values
    assert "Brand New Setting" in matrix["Configuration Item"].values


def test_zero_host_policy_is_excluded_from_matrix_and_compliance() -> None:
    policies = [
        {
            "id": "active-policy",
            "name": "Active Policy",
            "platform_name": "Windows",
            "enabled": True,
            "_member_count_collected": 5,
            "prevention_settings": [{
                "name": "On Write",
                "settings": [{"id": "DetectOnWrite", "name": "Detect on Write", "type": "toggle", "value": {"enabled": True}}],
            }],
        },
        {
            "id": "empty-policy",
            "name": "Empty Policy",
            "platform_name": "Windows",
            "enabled": True,
            "_member_count_collected": 0,
            "prevention_settings": [{
                "name": "On Write",
                "settings": [{"id": "DetectOnWrite", "name": "Detect on Write", "type": "toggle", "value": {"enabled": False}}],
            }],
        },
    ]
    groups, _, settings, _ = normalize_policies(policies, [], load_label_mapping(None))
    assert set(groups["Policy ID"]) == {"active-policy"}
    assert set(settings["Policy ID"]) == {"active-policy"}
    assessed = assess_settings(settings, None)
    matrix = policy_matrix_dataframe(groups, assessed, "Windows")
    assert "Active Policy" in matrix.columns
    assert "Empty Policy" not in matrix.columns
    summary = policy_summary(groups, assessed)
    windows = summary[summary["Platform"].eq("Windows")].iloc[0]
    assert windows["Policy Groups"] == 1
    assert windows["Total Policy Members"] == 5


def test_dynamic_default_best_practice_on_and_moderate_plus_plus() -> None:
    policies = [{
        "id": "baseline-policy",
        "name": "Baseline Policy",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 4,
        "prevention_settings": [
            {
                "name": "On Write",
                "settings": [
                    {"id": "DetectOnWrite", "name": "Detect on Write", "type": "toggle", "value": {"enabled": False}},
                ],
            },
            {
                "name": "Cloud Machine Learning",
                "settings": [
                    {"id": "CloudAntiMalware", "name": "Cloud Anti-malware", "type": "mlslider", "value": {"detection": "AGGRESSIVE", "prevention": "MODERATE"}},
                ],
            },
        ],
    }]
    groups, _, settings, _ = normalize_policies(policies, [], load_label_mapping(None))
    assessed = assess_settings(settings, None).set_index("Setting ID")
    assert assessed.loc["DetectOnWrite", "Best Practice"] == "ON"
    assert assessed.loc["DetectOnWrite", "Baseline Status"] == "Not Compliant"
    assert assessed.loc["CloudAntiMalware", "Best Practice"] == "MODERATE++"
    # Detection is above the threshold, but prevention=MODERATE is below MODERATE++.
    assert assessed.loc["CloudAntiMalware", "Baseline Status"] == "Not Compliant"


def test_custom_baseline_override_wins_over_dynamic_default() -> None:
    policies = [{
        "id": "custom-baseline",
        "name": "Custom Baseline",
        "platform_name": "Windows",
        "enabled": True,
        "_member_count_collected": 2,
        "prevention_settings": [{
            "name": "Notifications",
            "settings": [{"id": "EndUserNotifications", "name": "Notify End Users", "type": "toggle", "value": {"enabled": False}}],
        }],
    }]
    _, _, settings, _ = normalize_policies(policies, [], load_label_mapping(None))
    custom = load_baseline(pd.DataFrame([{
        "Platform": "Windows",
        "Item Match": "EndUserNotifications",
        "Best Practice": "Customer Preference",
        "Comparison Mode": "Exact",
        "Exclude": True,
    }]))
    assessed = assess_settings(settings, custom).iloc[0]
    assert assessed["Best Practice"] == "Customer Preference"
    assert assessed["Baseline Status"] == "Excluded"


def test_detection_severity_correlation_matches_yaml_logic() -> None:
    from detector.analytics import build_analytics

    records = [
        {"Alert ID": "1", "Hostname": "HOST-A", "Severity Name": "Critical", "Tactic": "Execution", "Technique": "PowerShell", "Created Timestamp": "2026-08-01T01:00:00+00:00"},
        {"Alert ID": "2", "Hostname": "HOST-A", "Severity Name": "High", "Tactic": "Execution", "Technique": "PowerShell", "Created Timestamp": "2026-08-01T02:00:00+00:00"},
        {"Alert ID": "3", "Hostname": "HOST-A", "Severity Name": "Informational", "Tactic": "Discovery", "Technique": "System Information Discovery", "Created Timestamp": "2026-08-01T03:00:00+00:00"},
        {"Alert ID": "4", "Hostname": "HOST-B", "Severity Name": "Medium", "Tactic": "Persistence", "Technique": "Registry Run Keys", "Created Timestamp": "2026-08-01T04:00:00+00:00"},
    ]
    analytics = build_analytics(records)

    exec_row = next(row for row in analytics["tactic_technique_by_severity"] if row["Tactic"] == "Execution")
    assert exec_row["Total Detection"] == 2
    assert exec_row["Critical"] == 1
    assert exec_row["High"] == 1
    assert exec_row["Severity Priority Score"] == 90  # (100 + 80) / 2
    assert exec_row["Priority"] == "Take Care"

    host_a = next(row for row in analytics["host_requiring_attention"] if row["Hostname"] == "HOST-A")
    assert host_a["Priority"] == "Take Care"
    assert host_a["Total Detection"] == 3

    host_b = next(row for row in analytics["host_requiring_attention"] if row["Hostname"] == "HOST-B")
    assert host_b["Priority"] == "Review"


def test_detection_unique_repetition_noise_logic() -> None:
    from detector.analytics import build_analytics

    records = []
    for idx in range(40):
        records.append({
            "Alert ID": str(idx),
            "Hostname": "NOISY-HOST",
            "Severity Name": "Informational",
            "Tactic": "Discovery",
            "Technique": "Query Registry",
        })
    analytics = build_analytics(records)
    host = analytics["unique_detection_per_host"][0]
    assert host["Unique Detection"] == 1
    assert host["Total Detection"] == 40
    assert host["Repetition Ratio"] == 40
    assert host["Severity Priority Score"] == 5
    assert host["Priority"] == "Monitor / Noise Review"


def test_detection_export_contains_severity_correlation_sheets() -> None:
    from src.detection_adapter import normalize_alerts_standalone

    raw_records = [
        {
            "composite_id": "critical-1",
            "created_timestamp": "2026-08-02T00:00:00Z",
            "status": "new",
            "severity_name": "Critical",
            "name": "Malicious PowerShell",
            "description": "Critical test detection",
            "tactic": "Execution",
            "technique": "PowerShell",
            "device": {"hostname": "HOST-C", "device_id": "aid-c"},
            "user_name": "tester",
            "filename": "powershell.exe",
            "cmdline": "powershell.exe -enc test",
            "sha256": "a" * 64,
        }
    ]
    report, raw = normalize_alerts_standalone(raw_records)
    workbook = build_alert_workbook(report, raw, {"collection_pages": 1, "truncated": False, "fql_filter": "sample"})
    names = workbook_sheet_names(workbook)
    assert "Tactic-Tech Severity" in names
    assert "Host Requiring Attention" in names
    assert "Unique Detection per Host" in names
    assert "Unique Tactic-Technique" in names
    assert "Critical Investigation" in names


def test_latest_sensor_matrix_from_supplied_release_tables() -> None:
    matrix = normalize_sensor_matrix(pd.read_csv(DATA / "sample_sensor_matrix.csv"))
    versions = set(zip(matrix["Platform"], matrix["Version"]))
    assert ("Windows", "8.10.21405") in versions
    assert ("Windows", "7.40.21306") in versions
    assert ("Windows", "7.39.21108") in versions
    assert ("Linux", "8.10.19402") in versions
    assert ("Linux", "7.40.19311") in versions
    assert ("Mac", "8.10.21306") in versions
    assert ("Mac", "7.40.21204") in versions
