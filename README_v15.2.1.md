# Seraphim Falcon Data Collector v15.2.1

Streamlit-based CrowdStrike PM collector and assessment tool.

## v15.2.1 highlights

- Prevention Policy remains API-first and dynamically discovers new Falcon settings.
- Prevention Policy groups with **0 assigned hosts are excluded** from matrix, policy inventory used for PM, disabled/non-compliant views, and compliance calculations.
- Built-in Best Practice is now generated dynamically from setting type:
  - Toggle / boolean protection: **ON**
  - ML / level settings: **minimum MODERATE++**
- Optional uploaded baseline is treated as an **override**. It is no longer required to populate Best Practice.
- Detection severity correlation from v15.2.0 remains unchanged: Alerts API + FQL collection, Python analytics, no CQL/NGSIEM dependency.
- Refreshed Windows, Linux, and Mac sensor release matrix from v15.2.0 remains included.

Run:

```bash
streamlit run app.py
```

See `CHANGELOG_v15.2.1.md` for implementation details.
