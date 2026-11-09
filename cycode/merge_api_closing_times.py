"""
Merge closing times (Last Status Change) and closing reasons from an API export into the
UI closed export, so the UI file keeps its full detail (repository, package, CVE, ...) and
gains what only the API has.

    # 1. fetch the same day through the API into a separate folder (keeps the UI files safe)
    python3 fetch_violations.py --date 05-Nov-2026 --folder 05-Nov-2026_api
    # 2. merge into the UI closed export of that date
    python3 merge_api_closing_times.py 05-Nov-2026 --api-folder 05-Nov-2026_api --dry-run
    python3 merge_api_closing_times.py 05-Nov-2026 --api-folder 05-Nov-2026_api

The UI export has no Detection Id, so rows are matched on (category, first detected to the
millisecond). Policy is NOT part of the key: the API and UI name policies differently
("Secrets detection" vs "Generic Secret/Password"). The API gives times as epoch
milliseconds; they are converted to ISO UTC. A UI row is filled only when its match is safe:
  * the key is unique on both sides, or
  * the key repeats but the API rows for it all carry the same closing time and the
    counts agree (so the pairing cannot matter).
Anything else is left blank and counted as ambiguous. Existing closing times are never
overwritten; where both files have one they are compared, which validates the join.
Adds Status Reason / Status Updated By Id for matched rows and marks the source in
"Last Status Change Source" ("api"). The UI file is copied to <name>.pre-merge.bak first.
"""
from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
BLANK = {"", "-", "nan", "None", "<NA>"}


def read_export(path: Path) -> pd.DataFrame:
    """Read a Cycode CSV, skipping the Filter/Value preamble when present. All cells stay text."""
    skip = 0
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for i, line in enumerate(fh):
            if "Violation category" in line:
                skip = i
                break
            if i > 20:
                raise SystemExit(f"{path.name}: no 'Violation category' header in the first 20 lines")
    return pd.read_csv(path, skiprows=skip, dtype=str, keep_default_na=False, encoding="utf-8-sig", low_memory=False)


def _filled(series: pd.Series) -> pd.Series:
    return ~series.astype(str).str.strip().isin(BLANK)


def to_ts(series: pd.Series) -> pd.Series:
    """Timestamps from ISO text or epoch milliseconds, as UTC."""
    text = series.astype(str).str.strip()
    epoch = text.str.fullmatch(r"\d{11,}")
    out = pd.to_datetime(text.where(~epoch), errors="coerce", utc=True, format="mixed")
    if epoch.any():
        out[epoch] = pd.to_datetime(pd.to_numeric(text[epoch]), unit="ms", utc=True)
    return out


def match_key(df: pd.DataFrame) -> pd.Series:
    when = to_ts(df["First detected"]).dt.floor("ms")
    return df["Violation category"].astype(str) + "|" + when.astype(str)


def merge(ui: pd.DataFrame, api: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    ui = ui.copy()
    api = api[api["Status"].isin(["Resolved", "Dismissed"]) & _filled(api["Last Status Change"])].copy()
    api["_ts"] = to_ts(api["Last Status Change"])
    api = api[api["_ts"].notna()]
    api["Last Status Change"] = api["_ts"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    ui["_k"], api["_k"] = match_key(ui), match_key(api)
    closed = ui["Status"].isin(["Resolved", "Dismissed"])
    ui_n = ui.loc[closed, "_k"].map(ui.loc[closed, "_k"].value_counts())

    grouped = api.groupby("_k")
    info = pd.DataFrame({
        "api_n": grouped.size(),
        "times": grouped["Last Status Change"].nunique(),
        "time": grouped["Last Status Change"].first(),
        "reason": grouped["Status Reason"].first() if "Status Reason" in api else "",
        "actor": grouped["Status Updated By Id"].first() if "Status Updated By Id" in api else "",
        "status": grouped["Status"].first(),
    })
    pos = ui.loc[closed, ["_k", "Status"]].join(ui_n.rename("ui_n")).join(info, on="_k", rsuffix="_api")
    in_api = pos["api_n"].notna()
    status_ok = pos["Status"] == pos["status"]
    safe = in_api & status_ok & (
        ((pos["ui_n"] == 1) & (pos["api_n"] == 1)) | ((pos["ui_n"] == pos["api_n"]) & (pos["times"] == 1))
    )
    had = _filled(ui.loc[closed, "Last Status Change"])

    # validate the join where both sides already have a closing time
    both = safe & had
    diff_h = ((to_ts(ui.loc[closed, "Last Status Change"])[both] - to_ts(pos.loc[both, "time"])).dt.total_seconds() / 3600)
    by_cat = diff_h.groupby(ui.loc[closed, "Violation category"][both]).median().round(1).to_dict() if both.any() else {}
    status_pairs = in_api & (pos["ui_n"] == 1) & (pos["api_n"] == 1)
    agree = None
    to_fill = safe & ~had
    idx = pos.index[to_fill]

    for column in ("Status Reason", "Status Updated By Id", "Last Status Change Source"):
        if column not in ui.columns:
            ui[column] = ""
    ui.loc[idx, "Last Status Change"] = pos.loc[to_fill, "time"]
    ui.loc[idx, "Last Status Change Source"] = "api"
    ui.loc[idx, "Status Reason"] = pos.loc[to_fill, "reason"].fillna("")
    ui.loc[idx, "Status Updated By Id"] = pos.loc[to_fill, "actor"].fillna("")
    # reasons are useful even where the UI file already had the time
    keep = pos.index[both]
    ui.loc[keep, "Status Reason"] = pos.loc[both, "reason"].fillna("")
    ui.loc[keep, "Status Updated By Id"] = pos.loc[both, "actor"].fillna("")

    stats = {
        "ui_closed_rows": int(closed.sum()),
        "already_had_time": int(had.sum()),
        "api_closed_rows": int(len(api)),
        "filled": int(to_fill.sum()),
        "validated_pairs": int(both.sum()),
        "status_agrees_pct": round(100 * float(status_ok[status_pairs].mean()), 1) if status_pairs.any() else None,
        "median_hours_ui_minus_api": round(float(diff_h.median()), 1) if both.any() else None,
        "within_1_min_pct": round(100 * float((diff_h.abs() <= 1 / 60).mean()), 1) if both.any() else None,
        "median_hours_by_category": by_cat,
        "no_api_match": int((~in_api & ~had).sum()),
        "ambiguous_or_status_mismatch": int((in_api & ~safe & ~had).sum()),
        "still_blank": int(((~had) & ~to_fill).sum()),
    }
    return ui.drop(columns="_k"), stats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("date", help="export date label, e.g. 05-Nov-2026")
    ap.add_argument("--folder", default=None, help="UI export folder (default: ./<date>)")
    ap.add_argument("--api-folder", default=None, help="folder holding the API export (default: ./<date>_api)")
    ap.add_argument("--dry-run", action="store_true", help="report what would change, write nothing")
    args = ap.parse_args()

    name = f"Cycode - All violations (closed) - {args.date}.csv"
    ui_path = Path(args.folder or HERE / args.date) / name
    api_path = Path(args.api_folder or HERE / f"{args.date}_api") / name
    for p in (ui_path, api_path):
        if not p.exists():
            raise SystemExit(f"missing {p}")
    print("Reading UI export...")
    ui = read_export(ui_path)
    print("Reading API export...")
    api = read_export(api_path)
    merged, stats = merge(ui, api)
    for key, value in stats.items():
        print(f"  {key:32} {value:,}" if isinstance(value, int) else f"  {key:32} {value}")
    matched_share = 1 - stats["no_api_match"] / max(1, stats["ui_closed_rows"] - stats["already_had_time"])
    if stats["status_agrees_pct"] is not None and stats["status_agrees_pct"] < 98:
        print("\nWARNING: status disagrees on unique pairs, so the match key is unreliable; do not use this merge.")
    if matched_share < 0.9:
        print(f"\nWARNING: only {matched_share:.0%} of rows without a time found an API match.")
    if stats["median_hours_ui_minus_api"] is not None and abs(stats["median_hours_ui_minus_api"]) > 1:
        print("\nNOTE: the UI and API closing times differ for the same findings (see median_hours_by_category). "
              "UI times equal the audit-log event time and are kept; API times only fill blanks.")
    if args.dry_run:
        print("Dry run: nothing written.")
        return
    backup = ui_path.with_name(ui_path.name + ".pre-merge.bak")
    if not backup.exists():
        shutil.copy2(ui_path, backup)
    merged.to_csv(ui_path, index=False, quoting=csv.QUOTE_ALL, encoding="utf-8-sig")
    print(f"Wrote {ui_path.name} (backup: {backup.name})")


if __name__ == "__main__":
    main()
