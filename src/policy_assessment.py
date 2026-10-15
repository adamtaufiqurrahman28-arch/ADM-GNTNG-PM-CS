from __future__ import annotations

from typing import Any

import pandas as pd


LEVEL_ORDER = {
    "disabled": 0,
    "off": 0,
    "none": 0,
    "cautious": 1,
    "moderate": 2,
    "moderate++": 3,
    "aggressive": 4,
    "extra aggressive": 5,
    "enabled": 1,
    "on": 1,
    "true": 1,
}

DEFAULT_TOGGLE_BEST_PRACTICE = "ON"
DEFAULT_LEVEL_BEST_PRACTICE = "MODERATE++"


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalize_level(value: Any) -> str:
    return _normalize_text(value).replace("_", " ")


def load_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """Load optional user baseline overrides.

    v15.2.1 always has a dynamic built-in baseline. Uploaded rules are treated
    as overrides and are evaluated before the generated defaults.
    """
    if df is None or df.empty:
        return pd.DataFrame(columns=["Platform", "Item Match", "Best Practice", "Comparison Mode", "Exclude"])
    lookup = {str(c).strip().lower(): str(c) for c in df.columns}
    platform_col = lookup.get("platform")
    item_col = lookup.get("item match") or lookup.get("item path") or lookup.get("item name") or lookup.get("item konfigurasi")
    best_col = lookup.get("best practice") or lookup.get("best_practice") or lookup.get("recommended")
    mode_col = lookup.get("comparison mode") or lookup.get("comparison_mode")
    exclude_col = lookup.get("exclude") or lookup.get("not applicable")
    if not item_col or not best_col:
        raise ValueError("Baseline membutuhkan kolom Item Match/Item Path dan Best Practice.")
    result = pd.DataFrame(
        {
            "Platform": df[platform_col].astype(str) if platform_col else "All",
            "Item Match": df[item_col].astype(str),
            "Best Practice": df[best_col],
            "Comparison Mode": df[mode_col].astype(str) if mode_col else "Exact",
            "Exclude": df[exclude_col] if exclude_col else False,
        }
    )
    return result


def build_default_baseline(settings: pd.DataFrame) -> pd.DataFrame:
    """Generate a future-proof baseline from the settings returned by Falcon.

    User requirement for v15.2.1:
    - Boolean/toggle protections -> ON.
    - ML/level settings -> minimum MODERATE++.

    The baseline is derived from API setting type/value shape, not from a static
    list of setting IDs. New Falcon settings therefore get a recommendation
    automatically when their type can be safely classified.
    """
    columns = ["Platform", "Item Match", "Best Practice", "Comparison Mode", "Exclude"]
    if settings is None or settings.empty:
        return pd.DataFrame(columns=columns)

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for _, row in settings.iterrows():
        platform = str(row.get("Platform") or "All").strip() or "All"
        item_match = str(row.get("Setting ID") or row.get("Item Key") or row.get("Item Path") or "").strip()
        if not item_match:
            continue
        signature = (platform.casefold(), item_match.casefold())
        if signature in seen:
            continue

        setting_type = _normalize_text(row.get("Setting Type"))
        display_value = _normalize_text(row.get("Display Value") or row.get("Current Value"))
        detection_value = _normalize_level(row.get("Detection Value"))
        prevention_value = _normalize_level(row.get("Prevention Value"))
        configuration_status = _normalize_text(row.get("Configuration Status"))

        is_toggle = (
            "toggle" in setting_type
            or display_value in {"on", "off", "enabled", "disabled", "true", "false"}
            or configuration_status in {"enabled", "disabled"}
        )
        has_level_components = any(
            value in LEVEL_ORDER and value not in {"on", "off", "enabled", "disabled", "true"}
            for value in (detection_value, prevention_value)
            if value
        )
        scalar_level = _normalize_level(display_value)
        is_level = (
            "slider" in setting_type
            or "level" in setting_type
            or has_level_components
            or scalar_level in {"cautious", "moderate", "moderate++", "aggressive", "extra aggressive"}
        )

        if is_toggle:
            best = DEFAULT_TOGGLE_BEST_PRACTICE
            mode = "Enabled"
        elif is_level:
            best = DEFAULT_LEVEL_BEST_PRACTICE
            # Require every populated detection/prevention component to meet
            # the minimum, not just one side of a compound ML setting.
            mode = "Minimum All"
        else:
            # Unknown future value shapes remain visible in the dynamic matrix,
            # but we do not invent a compliance rule for an unclassified type.
            continue

        rows.append(
            {
                "Platform": platform,
                "Item Match": item_match,
                "Best Practice": best,
                "Comparison Mode": mode,
                "Exclude": False,
            }
        )
        seen.add(signature)

    return pd.DataFrame(rows, columns=columns)


def _combined_baseline(settings: pd.DataFrame, baseline: pd.DataFrame | None) -> pd.DataFrame:
    generated = build_default_baseline(settings)
    custom = load_baseline(baseline) if baseline is not None and not baseline.empty else pd.DataFrame(columns=generated.columns)
    if custom.empty:
        return generated
    if generated.empty:
        return custom
    # Custom rows come first and therefore win in assess_settings matching.
    return pd.concat([custom, generated], ignore_index=True)


def assess_settings(settings: pd.DataFrame, baseline: pd.DataFrame | None) -> pd.DataFrame:
    if settings is None or settings.empty:
        return pd.DataFrame()
    result = settings.copy()
    result["Best Practice"] = ""
    result["Comparison Mode"] = ""
    result["Baseline Status"] = "No Baseline"
    result["Assessment Reason"] = "Tipe setting belum dapat diklasifikasikan untuk baseline otomatis."

    effective_baseline = _combined_baseline(result, baseline)
    if effective_baseline.empty:
        return result

    rules = effective_baseline.to_dict(orient="records")
    for index, row in result.iterrows():
        platform = _normalize_text(row.get("Platform"))
        path = _normalize_text(row.get("Item Path"))
        name = _normalize_text(row.get("Item Name"))
        setting_id = _normalize_text(row.get("Setting ID"))
        display_name = _normalize_text(row.get("Display Name"))
        matched = None
        for rule in rules:
            rule_platform = _normalize_text(rule.get("Platform"))
            if rule_platform not in {"", "all", "*", platform}:
                continue
            token = _normalize_text(rule.get("Item Match"))
            if token and (token in {path, name, setting_id, display_name} or token in path or token in setting_id):
                matched = rule
                break
        if matched is None:
            continue

        best = matched.get("Best Practice")
        mode = _normalize_text(matched.get("Comparison Mode") or "exact")
        exclude = bool(matched.get("Exclude")) or _normalize_text(best) in {
            "customer preference",
            "not applicable",
            "n/a",
        }
        result.at[index, "Best Practice"] = best
        result.at[index, "Comparison Mode"] = matched.get("Comparison Mode") or "Exact"
        if exclude:
            result.at[index, "Baseline Status"] = "Excluded"
            result.at[index, "Assessment Reason"] = "Dikecualikan oleh baseline override."
            continue

        current_text = _normalize_text(row.get("Display Value") or row.get("Current Value"))
        best_text = _normalize_level(best)
        if mode in {"minimum all", "minimum_all", "min all", "min_all"}:
            component_values = []
            for candidate in (row.get("Detection Value"), row.get("Prevention Value")):
                level_text = _normalize_level(candidate)
                if level_text:
                    component_values.append(level_text)
            if not component_values:
                component_values = [_normalize_level(current_text)] if current_text else []
            current_levels = [LEVEL_ORDER.get(value) for value in component_values]
            best_level = LEVEL_ORDER.get(best_text)
            compliant = bool(component_values) and best_level is not None and all(
                level is not None and level >= best_level for level in current_levels
            )
            reason = (
                f"Semua level saat ini ({', '.join(component_values) or '-'}) harus minimum {best_text or '-'}"
            )
        elif mode in {"minimum", "min", "min_level", "minimum level"}:
            level_text = _normalize_level(row.get("Prevention Value") or row.get("Detection Value") or current_text)
            current_level = LEVEL_ORDER.get(level_text)
            best_level = LEVEL_ORDER.get(best_text)
            compliant = current_level is not None and best_level is not None and current_level >= best_level
            reason = f"Level saat ini {level_text or '-'}; minimum {best_text or '-'}"
        elif mode in {"enabled", "boolean"}:
            compliant = row.get("Configuration Status") == "Enabled"
            reason = "Best Practice otomatis: item wajib ON/Enabled."
        else:
            compliant = current_text == _normalize_text(best)
            reason = f"Current={current_text or '-'}; Expected={_normalize_text(best) or '-'}"
        result.at[index, "Baseline Status"] = "Compliant" if compliant else "Not Compliant"
        result.at[index, "Assessment Reason"] = reason
    return result


def policy_summary(policies: pd.DataFrame, assessed_settings: pd.DataFrame) -> pd.DataFrame:
    if policies is None or policies.empty:
        return pd.DataFrame()

    # Defensive v15.2.1 filter: compliance only represents policies attached to
    # at least one host, even if callers pass an unfiltered dataframe.
    active_policies = policies.copy()
    if "Member Count" in active_policies.columns:
        active_policies = active_policies[pd.to_numeric(active_policies["Member Count"], errors="coerce").fillna(0).gt(0)]
    elif "Has Hosts" in active_policies.columns:
        active_policies = active_policies[active_policies["Has Hosts"].eq(True)]

    active_ids = set(active_policies.get("Policy ID", pd.Series(dtype=str)).astype(str))
    active_settings = assessed_settings.copy() if assessed_settings is not None else pd.DataFrame()
    if not active_settings.empty and active_ids and "Policy ID" in active_settings.columns:
        active_settings = active_settings[active_settings["Policy ID"].astype(str).isin(active_ids)]

    rows: list[dict[str, Any]] = []
    for platform in ["Windows", "Mac", "Linux"]:
        policy_subset = active_policies[active_policies["Platform"].eq(platform)]
        setting_subset = active_settings[active_settings["Platform"].eq(platform)] if not active_settings.empty else pd.DataFrame()
        applicable = setting_subset[setting_subset["Baseline Status"].isin(["Compliant", "Not Compliant"])] if not setting_subset.empty else pd.DataFrame()
        compliant = int(applicable["Baseline Status"].eq("Compliant").sum()) if not applicable.empty else 0
        assessed = len(applicable)
        rows.append(
            {
                "Platform": platform,
                "Policy Groups": len(policy_subset),
                "Enabled Policy Groups": int(policy_subset["Enabled"].eq(True).sum()) if not policy_subset.empty else 0,
                "Policy Groups with Hosts": len(policy_subset),
                "Total Policy Members": int(policy_subset["Member Count"].fillna(0).sum()) if not policy_subset.empty else 0,
                "Disabled Items": int(setting_subset["Configuration Status"].eq("Disabled").sum()) if not setting_subset.empty else 0,
                "Assessed Items": assessed,
                "Compliant Items": compliant,
                "Not Compliant Items": assessed - compliant,
                "Compliance %": (compliant / assessed * 100) if assessed else None,
            }
        )
    return pd.DataFrame(rows)
