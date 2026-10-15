# Dynamic Prevention Policy Matrix Update — v15.2.1

## Goal
Prevention Policy Matrix is now API-first and does not depend on a static list of known configuration items.

## Behavior
- Every section returned by Falcon Prevention Policy API is discovered automatically.
- Every setting returned by the API becomes a matrix row automatically.
- New future setting IDs do not require code or CSV changes to appear.
- `policy_setting_labels.csv` is now optional and functions only as a display/section/sort override.
- Settings without an override remain fully supported and are shown using Falcon's API-native name and section.
- CamelCase API IDs and snake_case override tokens are normalized consistently.
- Unknown/new value structures remain visible instead of becoming blank.
- Duplicate API IDs in different sections are handled defensively instead of being silently dropped.

## Verified with the supplied policy payload
The dynamic engine discovers these API settings without adding static mapping rows:
- `DetectPackageOnWrite` → `Detect Package on Write`
- `QuarantinePackageOnWrite` → `Quarantine Package on Write`

## Main changed files
- `app.py`
- `src/normalizers.py`
- `src/policy_mapping.py`
- `src/excel_exporter.py`
- `src/config.py`
- `tests/test_core.py`

## Optional legacy overrides
The old `data/policy_setting_labels.csv` is retained only as an optional presentation override and can be loaded from the Streamlit UI with **Load Legacy Display Overrides**.


## v15.2.1 compliance refinement
- Policy groups with 0 assigned hosts are excluded from report/compliance scope.
- Best Practice is generated dynamically: toggle = ON, ML/level = minimum MODERATE++.
- Uploaded baseline files are optional overrides, not required source-of-truth.
