# Seraphim Falcon Data Collector v15.2.1

## Prevention Policy compliance scope

- Policy groups with `Member Count <= 0` are filtered during normalization.
- Only active policy IDs are retained in normalized policy members/settings.
- Matrix, summary, Excel export, disabled items, and non-compliant items use active policies only.
- Raw API policy data is retained for troubleshooting/audit, but does not affect compliance.

## Dynamic Best Practice

A built-in baseline is generated from the actual Falcon API setting type/value shape instead of a static setting list:

- `toggle` / ON-OFF values -> Best Practice `ON`, comparison `Enabled`.
- `mlslider` / level values -> Best Practice `MODERATE++`, comparison `Minimum All`.
- For compound Detection/Prevention sliders, every populated level must meet `MODERATE++` or higher.
- Unknown future setting types remain visible in the matrix but are left `No Baseline` until they can be safely classified.
- Uploaded CSV/XLSX baseline rules are evaluated before generated rules and therefore act as overrides.

## Compatibility

- Dynamic Prevention Policy discovery from v15.1/v15.2 is preserved.
- FQL + severity-correlation Detection analytics from v15.2.0 is preserved.
- Sensor release matrix refresh from v15.2.0 is preserved.
