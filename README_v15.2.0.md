# Seraphim Falcon Data Collector v15.2.0

Run:

```bash
streamlit run app.py
```

Minimum Falcon API scopes used by the application:
- Hosts — Read
- Prevention Policies — Read
- Alerts — Read

v15.2.0 highlights:
1. Prevention Policy matrix is API-first and dynamically discovers future settings.
2. Detection collection uses Alerts API + FQL; severity correlation and aggregation run locally in Python without CQL/NGSIEM.
3. Default Windows, Linux, and Mac sensor release matrices were refreshed from the supplied 02 Sep 2026 release tables.

See `CHANGELOG_v15.2.0.md` for details.
