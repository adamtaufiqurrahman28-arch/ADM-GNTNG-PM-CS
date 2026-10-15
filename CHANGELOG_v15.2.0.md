# Seraphim Falcon Data Collector v15.2.0

## 1. Dynamic Prevention Policy Discovery
- Falcon API `prevention_settings` is the source of truth.
- Every API setting is automatically included in normalization and policy matrix output.
- Local `policy_setting_labels.csv` is optional presentation override only; it is never a whitelist/gate.
- Future Falcon settings therefore appear without adding code or CSV rows.

## 2. Detection: FQL Collection + Python Severity Correlation
Collection remains compatible with the existing standalone Alerts API flow:
- `Alerts.get_alerts_combined`
- date-range FQL and optional additional FQL
- `after` pagination
- no CQL and no NGSIEM dependency for analytics

The app now calculates the requested YAML-equivalent analytics locally:
- Detection by Severity
- Tactic & Technique by Severity
- Host Requiring Attention
- Unique Detection per Host
- Unique Tactic & Technique by Severity
- Critical Detection Investigation

Severity weights:
- Critical: 100
- High: 80
- Medium: 50
- Low: 20
- Informational: 5

Priority rules mirror the supplied dashboard logic:
- Critical or High present -> `Take Care`
- otherwise Medium present -> `Review`
- otherwise high volume/repetition -> `Monitor / Noise Review`
- otherwise -> `Monitor`

Legacy Top Host / Tactic / Technique views are retained for continuity.

## 3. Sensor Matrix Refresh (02 Sep 2026 input)
Default and template matrices were refreshed from the supplied Windows, Linux, and Mac release screenshots.
Latest rows include:
- Windows 8.10.21405, 7.40.21306, 7.39.21108/21105
- Linux 8.10.19402, 7.40.19311, 7.39.19204/19203
- Mac 8.10.21306, 7.40.21204, 7.39.21104/21103

The full supplied release rows and EOS dates are stored in `data/sample_sensor_matrix.csv` and `data/sensor_matrix_template.csv`.
