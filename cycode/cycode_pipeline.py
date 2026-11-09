"""
Pipeline for ingesting, normalizing, and conducting major analyses on Cycode data.
----------------------------------------------------------------------------------

Run:
----
    python3 -m cycode_pipeline
"""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha1
import math
import re
import sys
import traceback
import warnings
from pathlib import Path

import pandas as pd
import numpy as np

_ROOT_DIR = Path(__file__).resolve().parents[1]
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

NaN = float("nan")

try:
    from .merge_api_closing_times import *
except ImportError:  # pragma: no cover - support direct script execution
    from merge_api_closing_times import *

# This batch script only needs Stage 1. Importing app.py would execute the
# Streamlit application in bare Python and emit missing ScriptRunContext warnings.
class _LazyDetection:
    """Builds the heavy DetectionLayer on first use, so importing this module (e.g. from the
    deployed dashboard) does not need torch/langchain/faiss. Only the loaders touch it."""
    _layer = None

    def __getattr__(self, name):
        if _LazyDetection._layer is None:
            from vuln_intelligence_pipeline import DetectionLayer
            _LazyDetection._layer = DetectionLayer(enrich_external=False)
        return getattr(_LazyDetection._layer, name)


detection = _LazyDetection()

# def _normalized_frame(findings: list, normalizer) -> pd.DataFrame:
#     """Normalize one RawFinding at a time and return the rows that mapped."""
#     rows = []
#     for finding in findings:
#         row = normalizer(finding)
#         if row is not None:
#             rows.append(row)
#     return pd.DataFrame(rows)

def load_violations(path: str | Path, snapshot_ts: str) -> pd.DataFrame:
    """
    Load a Cycode violations CSV into a DataFrame (one row per violation, no dedupe).

    The shared schema merges Introduced At / First detected into a single
    first_observed_at, which hides the difference between "age of the code" and
    "time in Cycode". The raw dates and the triage tags are therefore kept as
    separate columns: introduced_at, first_detected_at, tag_test_file,
    tag_latest_code, tag_ai_verified.
    """
    ingested = detection._ingest_cycode_violations(path, snapshot_ts)
    rows = []
    for finding in ingested:
        row = detection._normalize_cycode_violations(finding)
        if row is None:
            continue
        raw = finding.raw_row
        tags = str(raw.get("Tags") or "").lower()
        row["introduced_at"] = raw.get("Introduced At")
        row["first_detected_at"] = raw.get("First detected")
        row["tag_test_file"] = "test file" in tags
        row["tag_latest_code"] = "exists in latest code" in tags
        row["tag_ai_verified"] = "verified by ai" in tags
        row["user"] = raw.get("User")  # SCM author; blank for most non-secret rows
        row["branch"] = raw.get("Branch")
        # Cycode's own status word (Open / Resolved / Dismissed). The shared
        # schema folds Dismissed into false_positive, so keep the original.
        row["status_raw"] = raw.get("Status")
        # For closed findings this equals the audit-log event time of the closing change.
        row["last_status_change"] = raw.get("Last Status Change")
        # Only the API fetch (fetch_violations.py) writes these two columns; the UI
        # export has neither. They let M3/M8 classify a closing without the audit log.
        row["status_reason"] = raw.get("Status Reason")
        row["status_updated_by_id"] = raw.get("Status Updated By Id")
        rows.append(row)
    return pd.DataFrame(rows)

# Columns that identify one finding inside an export. Used to detect a finding
# that appears in both the open and the closed export.
_IDENTITY_COLUMNS = [
    "violation_category", "policy", "repository", "identifier",
    "file_path", "line", "package_name", "first_detected_at",
]
_EXPECTED_STATUS = {"open": {"open"}, "closed": {"resolved", "dismissed"}}

def load_all_violations(
    paths: dict[str, str | Path], snapshot_ts: str, ui_path: str | Path, api_path: str | Path
) -> pd.DataFrame:
    """
    Load several Cycode violations exports and concatenate them into one frame.

    paths maps an export label to a file, e.g.
        {"open": "Cycode - All violations - 15-Oct-2026.csv",
         "closed": "Cycode - All violations (closed) - 15-Oct-2026.csv"}
    Each file goes through load_violations(), so the Filter/Value preamble is
    skipped and every column the metrics need is kept. The frames are stacked
    (columns are unioned; the closed export has a few extra columns) and an
    `export_source` column records which file each row came from.

    Checks:
      - labelled "open" / "closed" exports should hold only the matching
        statuses; a mismatch is reported with a warning, not silently kept.
      - a finding present in two exports is kept once, from the export that
        is not "open" (a closed copy is the later state); a warning says how
        many rows were dropped.
    The caller then applies the usual add_triage_and_age / mapping steps.
    """
    frames = []
    for label, path in paths.items():
        if label == "closed":
            ui = load_violations(ui_path, snapshot_ts)
            api = load_violations(api_path, snapshot_ts)
            frame = merge(ui, api)
        else:
            frame = load_violations(path, snapshot_ts)
            frame["export_source"] = label
            expected = _EXPECTED_STATUS.get(label)
            if expected is not None and not frame.empty:
                seen = set(frame["status_raw"].dropna().astype(str).str.lower())
                unexpected = seen - expected
                if unexpected:
                    warnings.warn(
                        f"export '{label}' contains unexpected statuses {sorted(unexpected)}"
                    )
        frames.append(frame)
    combined = pd.concat(frames, ignore_index=True, sort=False)

    identity = [column for column in _IDENTITY_COLUMNS if column in combined.columns]
    key = combined[identity].astype(str).agg("|".join, axis=1)
    sources_per_key = combined.groupby(key)["export_source"].transform("nunique")
    clash = sources_per_key.gt(1) & combined["export_source"].eq("open")
    if clash.any():
        warnings.warn(
            f"{int(clash.sum())} finding(s) appear in both the open and a closed export; "
            "keeping the closed copy"
        )
        combined = combined[~clash].reset_index(drop=True)
    return combined

def summarize_export_merge(violations_df: pd.DataFrame) -> pd.DataFrame:
    """Row counts by export and Cycode status; use it to sanity-check a merge."""
    return (
        violations_df.groupby(["export_source", "status_raw"], dropna=False)
        .size()
        .rename("rows")
        .reset_index()
    )

def load_audits(path: str | Path, snapshot_ts: str) -> pd.DataFrame:
    """
    Load a Cycode audit logs CSV into a DataFrame.

    The shared schema folds Action and User into one identifier string, so
    they are kept as separate columns here: event_time, user, action.
    Audit events carry no violation id, so they describe triage activity
    and configuration changes, not individual findings.
    """
    ingested = detection._ingest_cycode_audit_logs(path, snapshot_ts)
    rows = []
    for finding in ingested:
        row = detection._normalize_cycode_audit_logs(finding)
        if row is None:
            continue
        raw = finding.raw_row
        row["event_time"] = raw.get("Date")
        row["user"] = raw.get("User")
        row["action"] = raw.get("Action")
        rows.append(row)
    return pd.DataFrame(rows)

# --- Audit events <-> violations -------------------------------------------
# Neither export carries a shared id, so findings are linked on the closing
# timestamp. For a Resolved finding, the violations log's "Last Status Change"
# equals the audit event's "Date" to the microsecond, and both are unique, so
# the join is one-to-one. Category must also agree (checked, not assumed).
# Policy and File Path are NOT used: the audit log names secrets "Secrets
# detection" and reports CI/CD workflow names as the repository.

_AUDIT_DETECTION_COLUMNS = {
    "Date": "event_time",
    "Id": "event_id",
    "Actor Id": "actor_id",
    "Detection Id": "detection_id",
    "Old Status": "old_status",
    "New Status": "new_status",
    "Status Reason": "status_reason",
    "Status Change Message": "status_change_message",
    "Category": "category",
    "Policy": "policy_name",
    "Repository": "repository",
    "File Path": "file_path",
    "Line": "line",
}

def _to_utc(values: pd.Series) -> pd.Series:
    """Parse mixed ISO timestamps to UTC, truncated to microseconds."""
    return pd.to_datetime(values, errors="coerce", utc=True, format="mixed").dt.floor("us")

def load_audit_detection_events(path: str | Path) -> pd.DataFrame:
    """
    Load only the Detection status-change events from a Cycode audit log CSV.

    Much lighter than load_audits(): the full file is ~160k rows, of which about
    38k are Detection events. Returns one row per event with snake_case columns
    (event_time as UTC timestamp, detection_id, old_status, new_status,
    status_reason, actor_id, category, ...). The free-text Description column is
    not read (it can hold masked integration settings).
    """
    frame = pd.read_csv(
        path,
        usecols=["Resource Type", *_AUDIT_DETECTION_COLUMNS],
        low_memory=False,
        encoding="utf-8-sig",
    )
    frame = frame[frame["Resource Type"].eq("Detection")].drop(columns="Resource Type")
    frame = frame.rename(columns=_AUDIT_DETECTION_COLUMNS)
    frame["event_time"] = _to_utc(frame["event_time"])
    return frame.reset_index(drop=True)

def add_resolution_columns(
    violations_df: pd.DataFrame, events_df: pd.DataFrame | None = None
) -> pd.DataFrame:
    """
    Add the detection time and the resolution time to every finding.

    detected_at          UTC time Cycode first detected the finding (all rows).
    resolved_at          UTC time the finding was resolved. Set only when the
                         Cycode status is Resolved; Open and Dismissed rows are
                         left empty (a dismissal is not a remediation).
    resolved_at_source   why resolved_at has its value:
                           "audit_verified"     Last Status Change equals the time
                                                of a Resolved audit event for the
                                                same category
                           "last_status_change" from the violations log only
                                                (event is outside the audit window
                                                or the category disagrees)
                           "unavailable"        Resolved but no closing time known
                                                (all such rows are SCA today)
                         Empty for rows that are not Resolved.
    detection_id         Cycode detection id from the audit event (when matched).
    resolution_reason    audit Status Reason: Fixed, SourceRemoved, ...
    resolution_actor_id  audit Actor Id; empty means Cycode closed it itself
                         after a rescan.
    resolved_by          "actor" or "cycode_auto" for audit-matched rows.

    Rows are never dropped, and nothing here computes a duration: MTTR is
    resolved_at - detected_at, taken on rows where resolved_at_source is not
    "unavailable".
    """
    out = violations_df.copy()
    out["detected_at"] = _to_utc(out["first_detected_at"])
    resolved = out["status_raw"].astype(str).str.lower().eq("resolved")
    closing_time = _to_utc(out["last_status_change"])
    out["resolved_at"] = closing_time.where(resolved)

    source = pd.Series(pd.NA, index=out.index, dtype="object")
    source[resolved & closing_time.notna()] = "last_status_change"
    source[resolved & closing_time.isna()] = "unavailable"

    for column in ("detection_id", "resolution_reason", "resolution_actor_id", "resolved_by"):
        out[column] = pd.Series(pd.NA, index=out.index, dtype="object")

    if events_df is not None and not events_df.empty:
        events = events_df[events_df["new_status"].astype(str).str.lower().eq("resolved")]
        duplicated = events["event_time"].duplicated(keep=False)
        if duplicated.any():
            warnings.warn(
                f"{int(duplicated.sum())} Resolved audit events share a timestamp; "
                "those timestamps are not used for linking"
            )
            events = events[~duplicated]
        events = events.set_index("event_time")
        matched = events.reindex(out["resolved_at"])
        found = matched["detection_id"].notna().to_numpy() & resolved.to_numpy()
        same_category = (
            matched["category"].astype(str).to_numpy()
            == out["violation_category"].astype(str).to_numpy()
        )
        mismatch = found & ~same_category
        if mismatch.any():
            warnings.warn(
                f"{int(mismatch.sum())} row(s) matched an audit event on time but "
                "not on category; they were not linked"
            )
        linked = pd.Series(found & same_category, index=out.index)
        out.loc[linked, "detection_id"] = matched["detection_id"].to_numpy()[linked.to_numpy()]
        out.loc[linked, "resolution_reason"] = matched["status_reason"].to_numpy()[linked.to_numpy()]
        out.loc[linked, "resolution_actor_id"] = matched["actor_id"].to_numpy()[linked.to_numpy()]
        has_actor = out["resolution_actor_id"].notna()
        out.loc[linked & has_actor, "resolved_by"] = "actor"
        out.loc[linked & ~has_actor, "resolved_by"] = "cycode_auto"
        source[linked] = "audit_verified"

    # API exports carry the closing reason and actor on the finding itself. Use them
    # for Resolved rows the audit log could not classify (needs a closing time too).
    if "status_reason" in out.columns:
        api_reason = out["status_reason"].astype("object").where(
            ~out["status_reason"].astype(str).str.strip().isin(["", "-", "nan", "None", "<NA>"])
        )
        api_actor = out.get("status_updated_by_id", pd.Series(pd.NA, index=out.index)).astype("object")
        api_actor = api_actor.where(~api_actor.astype(str).str.strip().isin(["", "-", "nan", "None", "<NA>"]))
        use_api = resolved & out["resolution_reason"].isna() & api_reason.notna() & closing_time.notna()
        if use_api.any():
            out.loc[use_api, "resolution_reason"] = api_reason[use_api]
            out.loc[use_api, "resolution_actor_id"] = api_actor[use_api]
            out.loc[use_api & api_actor.notna(), "resolved_by"] = "actor"
            out.loc[use_api & api_actor.isna(), "resolved_by"] = "cycode_auto"
            source[use_api] = "api_status"

    out["resolved_at_source"] = source
    return out

def audit_coverage_warnings(violations_df: pd.DataFrame, events_df: pd.DataFrame | None) -> list[str]:
    """
    Explain Resolved findings that cannot be classified because the audit log
    does not cover the time they were closed.

    A Resolved row only gets a resolution reason (Fixed, SourceRemoved, ...) from
    the audit event with the same timestamp. If the audit log stops before a
    closing date (or starts after it), those rows have no reason and M3 / M8
    leave them out. Run after add_resolution_columns().
    """
    if events_df is None or events_df.empty or "event_time" not in events_df:
        return ["No audit events loaded: no Resolved finding can be classified, so M3 and M8 will be empty."]
    resolved = violations_df[violations_df["status_raw"].astype(str).str.lower().eq("resolved")]
    unlinked = resolved[resolved["resolution_reason"].isna()]
    if unlinked.empty:
        return []
    start, end = events_df["event_time"].min(), events_df["event_time"].max()
    closed = pd.to_datetime(unlinked["last_status_change"], errors="coerce", utc=True)
    after, before = int((closed > end).sum()), int((closed < start).sum())
    other = len(unlinked) - after - before
    out = []
    if after or before:
        parts = []
        if after:
            parts.append(f"{after:,} closed after the audit log ends ({end:%Y-%m-%d})")
        if before:
            parts.append(f"{before:,} closed before it starts ({start:%Y-%m-%d})")
        out.append(
            f"Audit log covers {start:%Y-%m-%d} to {end:%Y-%m-%d}: " + " and ".join(parts)
            + ". Those Resolved findings have no resolution reason and are excluded from M3 and M8. "
            "Re-fetch the audit log from the first scan date to today."
        )
    if other:
        out.append(f"{other:,} other Resolved findings have no matching audit event (excluded from M3 and M8).")
    return out


def summarize_resolution_link(violations_df: pd.DataFrame) -> pd.DataFrame:
    """Resolved rows by how their resolved_at was obtained, plus the reason mix."""
    resolved = violations_df[violations_df["status_raw"].astype(str).str.lower().eq("resolved")]
    return (
        resolved.groupby(["resolved_at_source", "resolution_reason"], dropna=False)
        .size()
        .rename("rows")
        .reset_index()
    )

_PROJECT_BY_REPO = {
    "workforce-intelligence": "Workforce Intelligence",
    "workforce-intelligence-infra": "Workforce Intelligence",
    "dev-workgraph": "Workforce Intelligence",
    "loop-brain": "Loop",
    "nexus": "Loop",
    "nexus-infra": "Loop",
    "tokclaw-apps": "Apps",
    "dolly": "Tempo for Jira",
    "tj-infrastructure": "Tempo for Jira",
    "TEMPO-JIRA-API": "Tempo for Jira",
    "content-intelligence": "Loop",
    "engineering-digest": "Other",
    "testing": "Other",
    "shared-tf-infrastructure": "Shared infra",
}
_TEAM_BY_REPO = {
    "workforce-intelligence": "X-Men",
    "workforce-intelligence-infra": "X-Men",
    "dev-workgraph": "Dev",
    "loop-brain": "Vanguard, The Rejects, Insights",
    "nexus": "Vanguard, The Rejects, Insights",
    "nexus-infra": "Vanguard, The Rejects, Insights",
    "tokclaw-apps": "TBA",
    "dolly": "Avengers",
    "tj-infrastructure": "Avengers",
    "TEMPO-JIRA-API": "Avengers",
    "content-intelligence": "Vanguard, The Rejects, Insights",
    "engineering-digest": "Dev",
    "testing": "Dev",
    "shared-tf-infrastructure": "Dev",
}
_RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def _repository_column(frame: pd.DataFrame) -> str:
    for name in ("repository", "Repository"):
        if name in frame.columns:
            return name
    raise KeyError("violations frame has no repository column")

def _repo_slug(value: object) -> str | None:
    """Return the repo name from either 'nexus' or 'tempo-io/nexus'."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    text = str(value).strip()
    if not text or text.lower() == "nan":
        return None
    return text.rsplit("/", 1)[-1]

# ---------------------------------------------------------------------------
# Product map: product_map.csv is the single source of truth
# ---------------------------------------------------------------------------
# One file drives project, team AND scanner-coverage reporting. The built-in
# dictionaries above are only the fallback when the file does not exist (and
# what the unit tests use). Edit the CSV, not the code, when the map changes.
PRODUCT_MAP_PATH = Path(__file__).resolve().parents[1] / "product_map.csv"
PRODUCT_MAP_COLUMNS = [
    "repo", "product_line", "team", "confidence", "in_cycode_export", "first_seen",
    "suggested_product_line", "suggested_team", "notes",
]
_LEGACY_COLUMNS = {"in_cycode_export_06oct": "in_cycode_export"}
UNMAPPED = "Unmapped"
_PRODUCT_MAP_SOURCE: object = "auto"  # "auto" | None (built-in) | path | DataFrame
_PRODUCT_MAP_CACHE: dict = {}


def use_product_map(source: object = "auto") -> None:
    """
    Choose where project/team mapping comes from:
      "auto"      product_map.csv if it exists, else the built-in dictionaries (default)
      None        built-in dictionaries only (used by the unit tests)
      path/frame  that file or DataFrame
    """
    global _PRODUCT_MAP_SOURCE
    _PRODUCT_MAP_SOURCE = source
    _PRODUCT_MAP_CACHE.clear()


def _strip_assumed(value: object) -> str:
    """'Loop (assumed)' and 'Loop' are the same product; the suffix only marks an unconfirmed mapping."""
    return re.sub(r"\s*\(assumed\)\s*$", "", str(value).strip())


def load_product_map(source: str | Path | pd.DataFrame | None = None) -> pd.DataFrame:
    """
    Read and normalise a product map. Accepts the current CSV or the older one
    (column in_cycode_export_06oct, no team column). Whitespace is stripped,
    blank product/team become 'Unmapped', repeated repos keep the first row.
    """
    if isinstance(source, pd.DataFrame):
        frame = source.copy()
    else:
        frame = pd.read_csv(source or PRODUCT_MAP_PATH, dtype=str, keep_default_na=False)
    frame = frame.rename(columns=_LEGACY_COLUMNS)
    if "team" not in frame.columns:  # older files: carry the built-in team over once
        frame["team"] = frame["repo"].map(lambda r: _TEAM_BY_REPO.get(str(r).strip(), ""))
    for column in PRODUCT_MAP_COLUMNS:
        if column not in frame.columns:
            frame[column] = ""
    frame = frame[PRODUCT_MAP_COLUMNS + [c for c in frame.columns if c not in PRODUCT_MAP_COLUMNS]]
    for column in frame.columns:
        frame[column] = frame[column].fillna("").astype(str).str.strip()
    frame = frame[frame["repo"] != ""]
    repeated = frame["repo"].str.lower().duplicated()
    if repeated.any():
        warnings.warn(f"product map repeats repos {sorted(frame.loc[repeated, 'repo'])}; first row kept")
        frame = frame[~repeated]
    for column in ("product_line", "team"):
        frame[column] = frame[column].map(_strip_assumed).replace("", UNMAPPED)
    return frame.reset_index(drop=True)


def _lookups(product_map: pd.DataFrame | None = None) -> tuple[dict, dict]:
    """(project_by_repo, team_by_repo), keys lower-cased so repo-name case never matters."""
    source = product_map if product_map is not None else _PRODUCT_MAP_SOURCE
    frame = None
    if isinstance(source, pd.DataFrame):
        frame = load_product_map(source)
    elif source == "auto" and PRODUCT_MAP_PATH.exists():
        frame = _cached_map(PRODUCT_MAP_PATH)
    elif source not in (None, "auto"):
        frame = _cached_map(Path(source))
    if frame is None:
        return ({k.lower(): v for k, v in _PROJECT_BY_REPO.items()},
                {k.lower(): v for k, v in _TEAM_BY_REPO.items()})
    keys = frame["repo"].str.lower()
    return dict(zip(keys, frame["product_line"])), dict(zip(keys, frame["team"]))


def _cached_map(path: Path) -> pd.DataFrame:
    stamp = (str(path), path.stat().st_mtime_ns)
    if stamp not in _PRODUCT_MAP_CACHE:
        _PRODUCT_MAP_CACHE.clear()
        _PRODUCT_MAP_CACHE[stamp] = load_product_map(path)
    return _PRODUCT_MAP_CACHE[stamp]


def _assign_lookup(frame: pd.DataFrame, column: str, lookup: dict[str, str]) -> pd.DataFrame:
    out = frame.copy()
    slugs = out[_repository_column(out)].map(_repo_slug)
    out[column] = slugs.map(lambda slug: lookup.get(str(slug).lower()) if slug else None).fillna(UNMAPPED)
    return out


def map_repository_to_project(violations_df: pd.DataFrame, product_map: pd.DataFrame | None = None) -> pd.DataFrame:
    """Map repository to project (product line) using the product map."""
    return _assign_lookup(violations_df, "Project", _lookups(product_map)[0])


def map_repository_to_team(violations_df: pd.DataFrame, product_map: pd.DataFrame | None = None) -> pd.DataFrame:
    """Map repository to team using the product map."""
    return _assign_lookup(violations_df, "Team", _lookups(product_map)[1])


def unmapped_repositories(violations_df: pd.DataFrame) -> pd.Series:
    """Repos with findings that have no product line yet, with their row counts (largest first)."""
    slugs = violations_df[_repository_column(violations_df)].map(_repo_slug)
    return slugs[violations_df["Project"].eq(UNMAPPED)].value_counts()

def _column(frame: pd.DataFrame, *names: str) -> str:
    for name in names:
        if name in frame.columns:
            return name
    raise KeyError(names[0])

def _mode(series: pd.Series):
    present = series.dropna()
    if present.empty:
        return None
    return present.mode().iloc[0]

TIER_ORDER = ["Actionable", "Review", "Noise"]

# Thresholds (document these on the executive page).
ACTIONABLE_MIN_SCORE = 70
NOISE_MAX_SCORE = 25

# Suggestions for NEW repos only. Labels (set in Cycode) are the stronger signal;
# repo-name prefixes are the fallback. A suggestion never changes product_line by
# itself; it is written next to it for you to confirm. Extend these as products appear.
LABEL_PRODUCT_HINTS = {
    "custom-charts": "Custom Charts",
    "roadmunk": "Strategic Roadmaps",
    "alpha-serve": "Alpha Serve",
    "structure": "Structure",
    "nexus": "Loop",
    "tempo-for-jira": "Tempo for Jira",
    "workforce-intelligence": "Workforce Intelligence",
    "portfolio-manager": "Portfolio Manager",
}
NAME_PRODUCT_HINTS = [
    ("custom-charts", "Custom Charts"), ("cc-", "Custom Charts"), ("roadm", "Strategic Roadmaps"),
    ("structure", "Structure"), ("as-", "Alpha Serve"), ("workforce", "Workforce Intelligence"),
    ("nexus", "Loop"), ("loop", "Loop"), ("tj-", "Tempo for Jira"),
    ("pfm_", "Portfolio Manager"), ("pfm-", "Portfolio Manager"),
    ("powerbi", "Alpha Serve"), ("bi-connector", "Alpha Serve"),
]


def _suggest_product(repo: str, labels: object) -> str:
    tokens = {t.strip().lower() for t in re.split(r"[\n|,]", str(labels or "")) if t.strip()}
    for label, product in LABEL_PRODUCT_HINTS.items():
        if label in tokens:
            return product
    name = repo.lower()
    words = set(re.split(r"[-_]", name))
    for fragment, product in NAME_PRODUCT_HINTS:
        # Whole words or a prefix ("as-"); never a substring, so "infrastructure" is not "structure".
        if name.startswith(fragment) or fragment.strip("-") in words:
            return product
    return ""


def update_product_mapping(
    by_repo: pd.DataFrame,
    product_map: pd.DataFrame | None = None,
    date_label: str | None = None,
    apply_suggestions: bool = False,
) -> tuple[pd.DataFrame, dict]:
    """
    Merge a Cycode "By repository" export into the product map, safely.

    Rules (so every future update behaves the same):
      * Existing rows are never overwritten: confirmed product_line / team /
        confidence / notes stay exactly as you set them.
      * Repos in the export but not in the map are appended with product_line
        and team = "Unmapped", confidence "TO CONFIRM", first_seen = date_label,
        plus suggested_product_line / suggested_team (from Cycode labels, then
        repo-name hints; the team is the most common team of that product).
        apply_suggestions=True copies suggestions into product_line/team.
      * The export lists a repo once per source (GitHub, CodeQL, AWS) and CodeQL
        rows have no organisation, so repos are matched by name, case-insensitively.
      * in_cycode_export is refreshed (yes/no) for every row from this export.
        Mapped repos absent from the export are reported, not removed.

    Returns (updated map, report) where report has new_repos, absent_from_export,
    and still_unmapped (repos with no product line after the update).
    """
    current = load_product_map(product_map if product_map is not None else None) \
        if (product_map is not None or PRODUCT_MAP_PATH.exists()) \
        else pd.DataFrame(columns=PRODUCT_MAP_COLUMNS)
    exported = by_repo.copy()
    name_col = "Repository Name" if "Repository Name" in exported.columns else "repository"
    exported["repo"] = exported[name_col].map(_repo_slug)
    exported = exported.dropna(subset=["repo"])
    labels_col = "Labels" if "Labels" in exported.columns else None
    # Keep the longest label text per repo (the GitHub row has labels; CodeQL rows do not).
    per_repo = exported.groupby(exported["repo"].str.lower()).agg(
        repo=("repo", "first"),
        labels=(labels_col, lambda s: max((str(v) for v in s if pd.notna(v)), key=len, default="")) if labels_col
        else ("repo", lambda s: ""),
    )
    in_export = set(per_repo.index)
    known = set(current["repo"].str.lower())

    out = current.copy()
    out["in_cycode_export"] = np.where(out["repo"].str.lower().isin(in_export), "yes", "no")

    team_by_product = (
        current[~current["team"].isin([UNMAPPED, ""]) & ~current["product_line"].eq(UNMAPPED)]
        .groupby("product_line")["team"].agg(lambda s: s.mode().iloc[0])
        .to_dict()
    )
    new_rows = []
    for key, row in per_repo.iterrows():
        if key in known:
            continue
        product = _suggest_product(row["repo"], row["labels"])
        team = team_by_product.get(product, "")
        new_rows.append({
            "repo": row["repo"],
            "product_line": product if (apply_suggestions and product) else UNMAPPED,
            "team": team if (apply_suggestions and team) else UNMAPPED,
            "confidence": "TO CONFIRM",
            "in_cycode_export": "yes",
            "first_seen": date_label or "",
            "suggested_product_line": product,
            "suggested_team": team,
            "notes": "new in the " + (date_label or "latest") + " By-repository export",
        })
    if new_rows:
        out = pd.concat([out, pd.DataFrame(new_rows)], ignore_index=True)
    out = out[PRODUCT_MAP_COLUMNS + [c for c in out.columns if c not in PRODUCT_MAP_COLUMNS]]
    report = {
        "new_repos": [r["repo"] for r in new_rows],
        "absent_from_export": sorted(out.loc[out["in_cycode_export"] == "no", "repo"]),
        "still_unmapped": sorted(out.loc[out["product_line"] == UNMAPPED, "repo"]),
    }
    return out, report


def write_product_map(product_map: pd.DataFrame, path: str | Path | None = None, backup: bool = True) -> Path:
    """Save the map; the previous file is kept as <name>.bak so a bad update is one copy away."""
    path = Path(path or PRODUCT_MAP_PATH)
    if backup and path.exists():
        path.with_suffix(path.suffix + ".bak").write_bytes(path.read_bytes())
    product_map.to_csv(path, index=False)
    _PRODUCT_MAP_CACHE.clear()
    return path


def add_missing_repos_to_product_map(
    product_map: pd.DataFrame,
    repo_slugs: list[str] | pd.Series,
    date_label: str | None = None,
    apply_suggestions: bool = False,
) -> tuple[pd.DataFrame, list[str]]:
    """
    Append violation repos that are not yet in the product map.

    Same rules as update_product_mapping for new rows: product_line/team stay
    Unmapped unless apply_suggestions=True; suggestions are always written.
    Returns (updated map, list of newly added repo names).
    """
    out = product_map.copy() if product_map is not None else pd.DataFrame(columns=PRODUCT_MAP_COLUMNS)
    known = set(out["repo"].astype(str).str.lower()) if len(out) and "repo" in out.columns else set()
    team_by_product = (
        out[~out["team"].isin([UNMAPPED, ""]) & ~out["product_line"].eq(UNMAPPED)]
        .groupby("product_line")["team"].agg(lambda s: s.mode().iloc[0])
        .to_dict()
        if len(out)
        else {}
    )
    new_rows = []
    for slug in sorted({str(s) for s in repo_slugs if pd.notna(s) and str(s).strip()}):
        if slug.lower() in known:
            continue
        product = _suggest_product(slug, "")
        team = team_by_product.get(product, "")
        new_rows.append({
            "repo": slug,
            "product_line": product if (apply_suggestions and product) else UNMAPPED,
            "team": team if (apply_suggestions and team) else UNMAPPED,
            "confidence": "TO CONFIRM",
            "in_cycode_export": "yes",
            "first_seen": date_label or "",
            "suggested_product_line": product,
            "suggested_team": team,
            "notes": "new from violations export " + (date_label or ""),
        })
        known.add(slug.lower())
    if new_rows:
        out = pd.concat([out, pd.DataFrame(new_rows)], ignore_index=True)
    return out, [r["repo"] for r in new_rows]


def resolve_repository_inventory(
    inventory_path: str | Path | None,
    date_label: str | None = None,
) -> Path | None:
    """
    Prefer the dated By-repository export; if it is missing, use the newest
    file with that name under the project data folders (M7 stays usable).
    """
    if inventory_path:
        preferred = Path(inventory_path).expanduser()
        if preferred.exists():
            return preferred
    search_dirs = [
        Path("~/Documents/Cycode Project/data").expanduser(),
        Path(__file__).resolve().parents[1] / "data",
        Path(__file__).resolve().parent / "data",
    ]
    candidates: list[Path] = []
    for folder in search_dirs:
        if folder.is_dir():
            candidates.extend(folder.glob("Cycode - By repository - *.csv"))
    if not candidates:
        return None

    def _stamp(path: Path) -> datetime:
        match = re.search(r"(\d{2}-[A-Za-z]{3}-\d{4})", path.name)
        if not match:
            return datetime.min
        try:
            return datetime.strptime(match.group(1), "%d-%b-%Y")
        except ValueError:
            return datetime.min

    newest = max(candidates, key=_stamp)
    if inventory_path:
        warnings.warn(
            f"repository inventory not found: {Path(inventory_path).expanduser()}; "
            f"using {newest.name} for M7 instead"
        )
    return newest


def classify_triage_tier(violations_df: pd.DataFrame) -> pd.Series:
    """
    Tier every violation: Actionable, Noise, or Review (everything in between).

    Actionable: High/Critical risk level AND risk score >= 70 AND severity >= Medium.
    Noise:      Low/Info risk level AND risk score < NOISE_MAX_SCORE AND severity Low/Info.
    Review:     all other rows, so tiers always sum to the total.
    """
    level = violations_df[_column(violations_df, "risk_level", "Risk Level")].astype(str).str.lower()
    score = pd.to_numeric(
        violations_df[_column(violations_df, "risk_score", "Risk Score")], errors="coerce"
    )
    severity = violations_df[_column(violations_df, "severity", "Severity")].map(
        lambda value: str(getattr(value, "value", value)).lower()
    )
    actionable = (
        level.isin(["high", "critical"])
        & score.ge(ACTIONABLE_MIN_SCORE)
        & severity.isin(["medium", "high", "critical"])
    )
    noise = level.isin(["low", "info"]) & score.lt(NOISE_MAX_SCORE) & severity.isin(["low", "info"])
    tier = pd.Series("Review", index=violations_df.index)
    tier[noise] = "Noise"
    tier[actionable] = "Actionable"
    return tier

def _days_before_snapshot(dates: pd.Series, snapshot: pd.Series) -> pd.Series:
    """Whole days from a date to the snapshot date (UTC); never negative."""
    when = pd.to_datetime(dates, errors="coerce", utc=True, format="mixed").dt.tz_localize(None).dt.normalize()
    as_of = pd.to_datetime(snapshot, errors="coerce", utc=True).dt.tz_localize(None).dt.normalize()
    return (as_of - when).dt.days.clip(lower=0)

def add_triage_and_age(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add triage_tier and the two separate age measures.

    detection_age_days: days since Cycode first detected it (all rows). This is
        time in Cycode, not time in the codebase; most of the backlog was first
        detected on the initial scan date, so read it as "time on our backlog".
    code_age_days: days since the code was introduced (Introduced At). Only
        populated for secrets (about a fifth of rows); blank otherwise. Never
        average it together with detection_age_days.
    """
    out = violations_df.copy()
    out["triage_tier"] = classify_triage_tier(out)
    out["detection_age_days"] = _days_before_snapshot(out["first_detected_at"], out["snapshot_ts"])
    out["code_age_days"] = _days_before_snapshot(out["introduced_at"], out["snapshot_ts"])
    return out

def _group_metrics(frame: pd.DataFrame, group_column: str, group: str) -> dict:
    subset = frame[frame[group_column] == group]
    policy = _column(subset, "policy", "Policy")
    repository = _repository_column(subset)
    risk_score = _column(subset, "risk_score", "Risk score", "Risk Score")
    risk_level = _column(subset, "risk_level", "Risk level", "Risk Level")
    severity = _column(subset, "severity", "Severity")
    ranks = subset[risk_level].map(
        lambda value: _RISK_RANK.get(str(value).lower(), None) if pd.notna(value) else None
    )
    severity_mode = _mode(subset[severity].map(lambda value: getattr(value, "value", value)))
    tiers = subset["triage_tier"].value_counts()
    actionable = subset[subset["triage_tier"] == "Actionable"]
    return {
        "total_violations": int(len(subset)),
        "actionable": int(tiers.get("Actionable", 0)),
        "review": int(tiers.get("Review", 0)),
        "noise": int(tiers.get("Noise", 0)),
        "unique_policies": int(subset[policy].nunique(dropna=True)),
        "total_repositories": int(subset[repository].nunique(dropna=True)),
        "average_risk_score": subset[risk_score].mean() if not subset[risk_score].isna().all() else "NA",
        "average_risk_level": ranks.mean() if not ranks.isna().all() else "NA",
        "average_severity": severity_mode,
        "median_detection_age_days_actionable": actionable["detection_age_days"].median(skipna=True) if not actionable["detection_age_days"].isna().all() else "NA",
        "median_code_age_days_actionable_secrets": actionable["code_age_days"].median(skipna=True) if not actionable["code_age_days"].isna().all() else "NA",
    }

def _summarize(frame: pd.DataFrame, group_column: str, order: list[str] | None) -> pd.DataFrame:
    """One row per group, plus a TOTAL row that must equal len(frame)."""
    present = [g for g in frame[group_column].dropna().unique()]
    groups = [g for g in (order or []) if g in present] + sorted(g for g in present if g not in (order or []))
    table = pd.DataFrame({g: _group_metrics(frame, group_column, g) for g in groups}).T
    total = 0 if table.empty else int(table["total_violations"].sum())
    if total != len(frame):
        raise ValueError(f"{group_column} summary covers {total} of {len(frame)} rows")
    table.index.name = group_column
    return table
            
projects = ["Workforce Intelligence", "Loop", "Apps", "Tempo for Jira", "Other", "Shared infra"]

def summarize_by_project(violations_df: pd.DataFrame, projects: list[str] = projects) -> pd.DataFrame:
    """
    Per-project summary. Requires add_triage_and_age() and map_repository_to_project().
    Groups not in `projects` (e.g. Unmapped) are appended, never dropped.
    average_risk_level is the mean of Critical=4, High=3, Medium=2, Low=1, Info=0.
    """
    return _summarize(violations_df, "Project", projects)

def summarize_by_team(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Per-team summary, a separate table from the project one so totals are never
    mixed. Team strings come from _TEAM_BY_REPO; a repo owned by several teams
    is one group (e.g. "Vanguard, The Rejects, Insights").
    """
    return _summarize(violations_df, "Team", None)

# =============================================================================
# CORE METRICS:
# =============================================================================
# Source of the metric list: metric_selection.qmd (9 metrics). Each function
# below is a documented stub: the docstring holds the definition, inputs, data
# readiness and pseudocode; the body raises NotImplementedError until built.
# Nothing here runs at import time or changes existing behaviour.
#
# Conventions used by every metric
# --------------------------------
# 1. Dimensions. Every metric is computed once per dimension in
#    DIMENSIONS = Project, Team, Repository and returned as its own table.
#    Never add values across dimensions: a finding is counted once per
#    dimension, so a Project total plus a Team total double counts it.
#    (The formulas in metric_selection.qmd add the three together; the
#    stubs below intentionally do not.)
# 2. Output shape. Every metric returns a "long" frame with columns
#       snapshot_date, metric, dimension, group, value, n, status, note
#    where n is the number of findings behind the value (suppress or flag
#    values with n < MIN_N) and status is one of READY / PARTIAL / BLOCKED.
#    One schema means the weekly history is a plain append and any
#    dashboard (Cycode, Streamlit, BI tool) can read it.
# 3. Stable finding key. Cross-snapshot metrics (trend, MTTR, remediations)
#    need to recognise the same finding in two exports. The pipeline's
#    `identifier` is not unique (SAST rows share category:policy), so use
#    finding_key = hash(source, repository, identifier, file_path, line,
#    package_name). Build it in add_finding_key() before any diffing.
# 4. Snapshot date comes from the export (snapshot_ts), never "today".

DIMENSIONS = ["Project", "Team", "Repository"]
MIN_N = 5  # below this many findings, flag the value as low-confidence

# Remediation SLAs in days by Risk Level. PLACEHOLDERS: agree with security
# and engineering leadership before presenting any SLA-based result.
SLA_DAYS = {"critical": 3, "high": 14, "medium": 90, "low": 180}

# Weights for the risk posture score. PLACEHOLDERS: to be agreed and then
# frozen so that week-to-week movement reflects findings, not re-weighting.
POSTURE_LEVEL_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 0.5, "info": 0}
POSTURE_TIER_MULTIPLIER = {"Actionable": 1.0, "Review": 0.25, "Noise": 0.0}

# Readiness of each metric against the 07-Oct-2026 violations export alone,
# and what unlocks the rest. Keep in step with the stubs below.
METRIC_SPECS = [
    {"id": "M1", "name": "actionable_open_high_critical", "ready_now": "READY",
     "needs": []},
    {"id": "M2", "name": "backlog_trend_new_vs_resolved", "ready_now": "PARTIAL",
     "needs": ["previous snapshot", "resolved findings"]},
    {"id": "M3", "name": "mttr_by_severity", "ready_now": "BLOCKED",
     "needs": ["resolved findings with a resolution date"]},
    {"id": "M4", "name": "noise_reduction_policy_tuning", "ready_now": "PARTIAL",
     "needs": ["audit logs", "previous snapshots for before/after"]},
    {"id": "M5", "name": "vulnerability_age_hygiene", "ready_now": "READY",
     "needs": ["agreed SLAs"]},
    {"id": "M6", "name": "ai_leverage", "ready_now": "PARTIAL",
     "needs": ["audit logs", "reachability output from vuln_intelligence_pipeline"]},
    {"id": "M7", "name": "scanner_coverage", "ready_now": "PARTIAL",
     "needs": ["repository inventory export (including repos with 0 findings)"]},
    {"id": "M8", "name": "remediations_vs_ai_cost", "ready_now": "BLOCKED",
     "needs": ["resolved findings", "AI cost data (not in Cycode)"]},
    {"id": "M9", "name": "risk_posture_score", "ready_now": "READY",
     "needs": ["agreed weights"]},
]

def _is_unique(series: pd.Series) -> bool:
    """
    Return True if the series is unique, False otherwise.
    """
    return series.nunique() == len(series)
    
def add_finding_key(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    PSEUDOCODE
        parts = [source, repository, identifier, file_path, line, package_name]
        finding_key = sha1("|".join(str(p) for p in parts))
        assert finding_key is unique within one snapshot, else log the
        duplicate rows (they inflate counts) and keep a dup_rank column.
    """
    parts = ["source", "repository", "identifier", "file_path", "line", "package_name"]
    out = violations_df.drop_duplicates(subset=parts).copy()
    material = out[parts].map(
        lambda value: "" if pd.isna(value) else str(value)
    ).agg("|".join, axis=1)
    finding_key = material.map(lambda text: sha1(text.encode("utf-8")).hexdigest())
    if not _is_unique(finding_key):
        raise ValueError("duplicate rows found")
    out["finding_key"] = finding_key
    return out

def impute_missing_fields(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Fill gaps so metrics never silently drop rows. Never overwrite a real value.

    PSEUDOCODE
        Project / Team : from the repo map; unmapped -> "Unmapped"
                         (report the % unmapped on every digest)
        Repository     : if blank, take it from Repository URL, then
                         Resource Path; else "Unknown repo" (AWS container
                         findings often have no repo: map via Resource Name /
                         registry path when the container filter is exported)
        Owner (User)   : blank for ~55% of rows; fall back to repo-level
                         owner team, never to a person
        Age            : detection_age_days always available; code_age_days
                         blank unless secret (do NOT impute, report as n/a)
        Resolved date  : see M3 for the fallback order
        Add one boolean column per imputed field (e.g. project_imputed) so a
        reviewer can see how much of a metric rests on imputation.
    """
    violations_full = violations_df.copy()
    violations_full["project"] = violations_df.map(map_repository_to_project)
    violations_full["team"] = violations_df.map(map_repository_to_team)
    if violations_full.__contains__(NaN):
        violations_full.fillna("To be determined", inplace=True)

    return violations_full

def metric_actionable_open_high_critical(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    M1. Actionable open High/Critical findings per Project / Team / Repository.

    Definition: open findings in the Actionable tier (High/Critical risk level,
    risk score >= 70, severity >= Medium). Counted once per dimension.
    Why: the headline number executives can act on; filters out the
    Review/Noise bulk of the backlog.
    Data: Status, triage_tier, Risk Level. READY on a single snapshot.

    PSEUDOCODE
        open_ = df[Status == "Open"]
        act   = open_[triage_tier == "Actionable"]
        optional filters (parameters, default off, reported when on):
            exclude tag_test_file ; require tag_latest_code
        for dim in DIMENSIONS:
            value[group] = count(act grouped by dim)
            also split by Violation category and by Risk Level
            n[group]     = same count
        return long frame (metric="actionable_open_high_critical")
    Sample check (07-Oct): 155 actionable of 992 rows.
    """
    reduced_violations_df = reduce_noise_repetitive_violations(violations_df)
    status = reduced_violations_df["status"].map(lambda value: str(getattr(value, "value", value)).lower())
    open_ = reduced_violations_df[status.eq("open")]
    actionable = open_[open_["triage_tier"].eq("Actionable")]
    level = actionable["risk_level"].astype(str).str.lower()
    score = pd.to_numeric(actionable["risk_score"], errors="coerce")
    severity = actionable["severity"].map(
        lambda value: str(getattr(value, "value", value)).lower()
    )
    high_critical = actionable[
        level.isin(["high", "critical"])
        & score.ge(70)
        & severity.isin(["medium", "high", "critical"])
    ]

    rows = []
    snapshot = reduced_violations_df["snapshot_ts"].iloc[0]
    for dim in DIMENSIONS:
        keys = _dimension_series(high_critical, dim)
        if keys is None:
            continue
        counts = high_critical.groupby(keys, dropna=True).size()
        for group, count in counts.items():
            rows.append({
                "snapshot_date": snapshot,
                "metric": "actionable_open_high_critical",
                "dimension": dim,
                "group": group,
                "value": int(count),
                "n": int(count),
                "status": "READY",
            })
    return pd.DataFrame(rows)

def metric_backlog_trend(
    current_df: pd.DataFrame, previous_df: pd.DataFrame | None = None
) -> pd.DataFrame:
    """
    M2. Backlog trend: new vs. resolved between snapshots.

    Definition: compare open finding_keys in the current snapshot with the
    previous one. new = open now but not then; resolved = open then but not
    now; net = new - resolved. Per Project / Team / Repository.
    Why: shows whether the program is winning, not just the snapshot size.
    Data: single snapshot -> PARTIAL (resolved unknown); two snapshots -> READY.

    first_detected_at is parsed with pandas (mixed ISO, including Cycode's
    7-digit fractional seconds). A strict strptime format will not work.
    """
    if current_df is None or current_df.empty:
        return pd.DataFrame()
    current = current_df if "finding_key" in current_df.columns else add_finding_key(current_df)
    snapshot = current["snapshot_ts"].iloc[0]

    if previous_df is None or previous_df.empty:
        # One snapshot can count new findings, not what left the backlog.
        return pd.DataFrame({
            "snapshot_date": [snapshot],
            "metric": ["backlog_trend"],
            "resolved": [pd.NA],
            "status": ["PARTIAL"],
            "note": ["no previous snapshot; resolved unknown"],
        })

    previous = previous_df if "finding_key" in previous_df.columns else add_finding_key(previous_df)

    rows = []
    for dim in DIMENSIONS:
        key_cur = _dimension_series(current, dim)
        key_prev = _dimension_series(previous, dim)
        if key_cur is None or key_prev is None:
            continue
        cur_map = (
            current.assign(_g=key_cur)
            .dropna(subset=["_g"])
            .drop_duplicates("finding_key")
            .set_index("finding_key")["_g"]
        )
        prev_map = (
            previous.assign(_g=key_prev)
            .dropna(subset=["_g"])
            .drop_duplicates("finding_key")
            .set_index("finding_key")["_g"]
        )
        groups = sorted(set(cur_map.unique()) | set(prev_map.unique()), key=str)
        for group in groups:
            cur_keys = set(cur_map[cur_map == group].index)
            prev_keys = set(prev_map[prev_map == group].index)
            n_new = len(cur_keys - prev_keys)
            n_resolved = len(prev_keys - cur_keys)
            rows.append({
                "snapshot_date": snapshot,
                "metric": "backlog_trend",
                "dimension": dim,
                "group": group,
                "new": n_new,
                "resolved": n_resolved,
                "net": n_new - n_resolved,
                "value": n_new - n_resolved,
                "n": len(cur_keys),
                "status": "READY",
                "note": "new = open now but not in previous snapshot; resolved = open then but not now",
            })
    return pd.DataFrame(rows)

def _dedup_by_issue(frame: pd.DataFrame) -> pd.DataFrame:
    """One row per (issue_key, status_raw); needs no triage columns. Used for counts/weights."""
    keyed = frame if "issue_key" in frame.columns else add_issue_key(frame)
    status = keyed["status_raw"] if "status_raw" in keyed.columns else keyed["status"].astype(str)
    return keyed.loc[~(keyed["issue_key"].astype(str) + "|" + status.astype(str)).duplicated()]

def _fixed_issues(resolved_df: pd.DataFrame) -> pd.DataFrame:
    """
    Fixed remediations collapsed to one row per issue, with correct times.

    A row counts only if Resolved, closing time known (not "unavailable") and
    reason Fixed. Rows of the same issue (issue_key) are merged:
      detected_at = earliest detection of any occurrence
      resolved_at = LAST occurrence closed (the issue is fixed only then)
      occurrences = rows merged
    Severity is the highest among the occurrences. This is deliberately NOT
    reduce_noise_repetitive_violations, whose representative row is chosen by
    triage tier and risk score and would give an arbitrary closing time.
    Needs add_resolution_columns(); needs no triage columns.
    """
    required = {"status_raw", "resolved_at", "resolved_at_source", "resolution_reason", "detected_at"}
    missing = required - set(resolved_df.columns)
    if missing:
        raise ValueError(f"run add_resolution_columns() first; missing {sorted(missing)}")
    keep = (
        resolved_df["status_raw"].astype(str).str.lower().eq("resolved")
        & resolved_df["resolved_at"].notna()
        & resolved_df["resolved_at_source"].ne("unavailable")
        & resolved_df["resolution_reason"].eq("Fixed")
    )
    fixed = resolved_df[keep]
    if fixed.empty:
        return fixed.copy()
    fixed = fixed if "issue_key" in fixed.columns else add_issue_key(fixed)
    sev_rank = fixed["severity"].map(
        lambda value: _RISK_RANK.get(str(getattr(value, "value", value)).lower(), -1)
    )
    grouped = fixed.groupby("issue_key")
    ordered = fixed.assign(_sev=sev_rank).sort_values("_sev", ascending=False, kind="mergesort")
    out = ordered.drop_duplicates("issue_key").drop(columns="_sev").copy()
    out["detected_at"] = out["issue_key"].map(grouped["detected_at"].min())
    out["resolved_at"] = out["issue_key"].map(grouped["resolved_at"].max())
    out["occurrences"] = out["issue_key"].map(grouped.size())
    return out

def metric_mttr_by_severity(
    resolved_df: pd.DataFrame, audits_df: pd.DataFrame | None = None
) -> pd.DataFrame:
    """
    M3. Mean/median time to remediate, by severity, per dimension.

    Definition: resolved_at - first_detected_at in days, grouped by severity
    (Critical/High/Medium/Low) within each dimension. Report median and p90
    alongside the mean; one very old fix distorts the mean.
    Data: BLOCKED today (8 Resolved rows in the 02-Oct file, none in later
    exports; Last Status Change is empty). Needs a finding-level status
    history export from Cycode, or two or more snapshots.

    PSEUDOCODE
        resolved_at, in order of preference:
            1. Last Status Change (when populated)
            2. date of the snapshot in which the finding first disappeared,
               minus half the snapshot gap (midpoint estimate)
            3. audit-log Detection "Modified" events; they carry no finding
               id, so use only for volume, not for per-finding time
        record which source produced each resolved_at (resolved_at_source)
        ttr_days = resolved_at - first_detected_at
        for dim in DIMENSIONS:
            for severity in [Critical, High, Medium, Low]:
                emit mean, median, p90, n   (flag n < MIN_N)
        report one row per severity, not a sum across severities.
    """
    if resolved_df.empty:
        return pd.DataFrame()
    snapshot = resolved_df["snapshot_ts"].iloc[0]  # one value, not the whole column

    # One row per fixed ISSUE (repeats merged; earliest detection to last closing).
    # Only fixes with a known closing time count: status Resolved, a resolved_at,
    # not "unavailable", and a Fixed reason (SourceRemoved and dismissals are not fixes).
    fixed = _fixed_issues(resolved_df).copy()
    if fixed.empty:
        return pd.DataFrame()
    fixed["ttr_days"] = (fixed["resolved_at"] - fixed["detected_at"]).dt.total_seconds() / 86400
    fixed["_severity"] = fixed["severity"].map(lambda value: str(getattr(value, "value", value)).title())
    general_ttr_days = fixed["ttr_days"].mean()

    resolved_rows = resolved_df[resolved_df["status_raw"].astype(str).str.lower().eq("resolved")]
    unclassified = resolved_rows[resolved_rows["resolution_reason"].isna()]
    unclassified_by_group = {}
    for dim in DIMENSIONS:
        keys = _dimension_series(unclassified, dim)
        unclassified_by_group[dim] = keys.value_counts().to_dict() if keys is not None else {}

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(fixed, dim)
        if key is None:
            continue
        for (group, severity), subset in fixed.groupby([key, fixed["_severity"]], dropna=True):
            rows.append({
                "snapshot_date": snapshot,
                "metric": "mttr_by_severity",
                "dimension": dim,
                "group": group,
                "severity": severity,
                "general_ttr_days": general_ttr_days,
                "ttr_days_mean": subset["ttr_days"].mean(),
                "ttr_days_median": subset["ttr_days"].median(),
                "ttr_days_p90": subset["ttr_days"].quantile(0.9),
                "ttr_days_n": int(subset["ttr_days"].count()),
                "n": int(len(subset)),
                # Resolved rows of this group with no resolution reason: excluded above,
                # so a blank or thin MTTR may be an audit-coverage gap, not a real absence.
                "resolved_unclassified": int(unclassified_by_group[dim].get(group, 0)),
                "status": "READY",
            })
    return pd.DataFrame(rows)

def _dimension_series(frame: pd.DataFrame, dimension: str) -> pd.Series | None:
    """
    Group keys for a dimension: 'Project', 'Team', or 'Repository'.

    Repository is reduced to its slug ('tempo-io/nexus' and 'nexus' are the
    same repo; CodeQL rows arrive without the organisation prefix).
    """
    column = dimension if dimension in frame.columns else dimension.lower()
    if column not in frame.columns:
        return None
    values = frame[column]
    return values.map(_repo_slug) if dimension == "Repository" else values

def metric_noise_reduction(
    violations_df: pd.DataFrame,
    # audits_df: pd.DataFrame | None = None,
    # history: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """
    M4. Noise reduction / policy-tuning impact.

    Definition (two parts):
      a) noise_rate = Noise-tier findings / total, and noise concentration:
         the share of all findings produced by the top 5 policies
         (e.g. "Leakage of information in logger message" was 49% of the
         02-Oct file).
      b) tuning impact = findings avoided after a tuning change, compared
         with the pre-change trend.
    Repetition adjustment: Cycode creates one row per occurrence, so rows
    overstate the work. Rows are collapsed to distinct issues with
    reduce_noise_repetitive_violations (issue_key; distinct secrets, packages
    and locations are never merged) and reported per group as issues,
    repeat_factor, duplicate_share_pct, noise_rate_issues (an issue is Noise
    only if every occurrence is Noise), actionable_issues and
    noise_reduction_pts = noise_rate - noise_rate_issues. The rate drop comes
    from repetition, not from tuning; say so when presenting it.
    Data: (a) READY from one snapshot. (b) PARTIAL: audit logs show when
    classification rules, risk-score formula or detections changed
    (ClassificationRule, Risk Score Formula, Detection events), but need
    weekly history to measure the effect.

    PSEUDOCODE
        (a) per dimension: noise_rate = noise / total
            top_policies = policy counts sorted desc ; pareto share of top 5
        (b) changes = audits[Resource Type in {ClassificationRule,
                              Risk Score Formula, Detection}]
            for each change date d:
                before = mean weekly findings (affected policy) over 4 weeks < d
                after  = mean weekly findings (affected policy) over 4 weeks >= d
                impact = before - after
            attribute impact to the change only if no other change touched the
            same policy in that window; otherwise mark status = "confounded"
    """
    if violations_df.empty:
        return pd.DataFrame()
    snapshot = violations_df["snapshot_ts"].iloc[0]
    general_noise_rate = round(100 * violations_df["triage_tier"].eq("Noise").mean(), 2)

    # Repetition-adjusted view: repeats of the same issue (issue_key, see
    # add_issue_key) collapse to one row, so noise is also reported per distinct
    # issue. An issue counts as Noise only if every occurrence is Noise.
    # Needs risk_score; without it these columns stay NaN rather than failing M4.
    try:
        reduced = reduce_noise_repetitive_violations(violations_df)
    except KeyError:
        reduced = None
    general_issue_noise_rate = (
        round(100 * reduced["triage_tier"].eq("Noise").mean(), 2) if reduced is not None else float("nan")
    )

    def _dedup_fields(group, key_series, reduced_key) -> dict:
        nan = float("nan")
        if reduced is None:
            return {"issues": nan, "repeat_factor": nan, "duplicate_share_pct": nan,
                    "noise_issues": nan, "noise_rate_issues": nan,
                    "actionable_issues": nan, "noise_reduction_pts": nan}
        issues = reduced[reduced_key == group]
        n_rows = int((key_series == group).sum())
        n_issues = len(issues)
        noise_issues = int(issues["triage_tier"].eq("Noise").sum())
        rows_noise_rate = 100 * float((violations_df.loc[key_series == group, "triage_tier"] == "Noise").sum()) / n_rows
        issue_rate = round(100 * noise_issues / n_issues, 2) if n_issues else nan
        return {
            "issues": n_issues,
            "repeat_factor": round(n_rows / n_issues, 1) if n_issues else nan,
            "duplicate_share_pct": _pct(n_rows - n_issues, n_rows),
            "noise_issues": noise_issues,
            "noise_rate_issues": issue_rate,
            "actionable_issues": int(issues["triage_tier"].eq("Actionable").sum()),
            # Percentage points the noise rate falls once repeats are collapsed.
            "noise_reduction_pts": round(rows_noise_rate - issue_rate, 2) if n_issues else nan,
        }

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(violations_df, dim)
        if key is None:
            continue
        reduced_key = _dimension_series(reduced, dim) if reduced is not None else None
        for group, subset in violations_df.groupby(key, dropna=True):
            policy_counts = subset["policy"].value_counts()
            noise_policies = subset.loc[subset["triage_tier"].eq("Noise"), "policy"].value_counts()
            noise_count = int(subset["triage_tier"].eq("Noise").sum())
            rows.append({
                "snapshot_date": snapshot,
                "metric": "noise_reduction",
                "dimension": dim,
                "group": group,
                "general_noise_rate": general_noise_rate,
                "noise_count": noise_count,
                "total": int(len(subset)),
                "noise_rate": round(100 * noise_count / len(subset), 2),
                "top_policy": policy_counts.index[0] if len(policy_counts) else None,
                "top_policy_share_pct": round(100 * policy_counts.iloc[0] / len(subset), 1),
                "top5_policy_share_pct": round(100 * policy_counts.head(5).sum() / len(subset), 1),
                "top_noise_policies": ", ".join(f"{p} ({c})" for p, c in noise_policies.head(3).items()),
                "general_issue_noise_rate": general_issue_noise_rate,
                **_dedup_fields(group, key, reduced_key),
                "n": int(len(subset)),
                "status": "PARTIAL",
                "note": "noise rate (rows and distinct issues) and policy concentration; "
                "tuning impact needs audit logs + weekly history"
                + ("; low n" if len(subset) < MIN_N else ""),
            })
    return pd.DataFrame(rows)

def metric_vulnerability_age(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    M5. Vulnerability age (hygiene score).

    Definition: age of the open Actionable backlog, reported in two
    separate measures and an SLA-based score.
      detection_age_days : time since Cycode first detected the finding.
      code_age_days      : time since the code was introduced; secrets only.
      hygiene_score      : 100 * (1 - sla_breached / actionable_open)
    Why: separates "how long has this sat on our backlog" from "how old is
    the vulnerable code". Never average the two measures together.
    Data: READY. SLA values in SLA_DAYS are placeholders.

    PSEUDOCODE
        act = open Actionable findings
        act["sla_days"]     = SLA_DAYS[Risk Level lower-cased]
        act["sla_breached"] = detection_age_days > sla_days
        for dim in DIMENSIONS:
            emit median, p90 of detection_age_days
            emit median of code_age_days (secrets only, with its own n)
            emit sla_breached_count and hygiene_score
        caveat: most of the backlog was first detected on the initial scan
        date, so early weeks measure "time since onboarding". State the
        baseline date next to the number.
    """
    if violations_df.empty:
        return pd.DataFrame()
    reduced_frame = reduce_noise_repetitive_violations(violations_df)
    # Ages are measured against the snapshot date, never today's date.
    if "detection_age_days" not in reduced_frame.columns or "code_age_days" not in reduced_frame.columns:
        reduced_frame = add_triage_and_age(reduced_frame)
    status = reduced_frame["status"].map(lambda value: str(getattr(value, "value", value)).lower())
    actionable = reduced_frame[status.eq("open") & reduced_frame["triage_tier"].eq("Actionable")].copy()
    snapshot = reduced_frame["snapshot_ts"].iloc[0]
    if actionable.empty:
        return pd.DataFrame()

    actionable["sla_days"] = actionable["risk_level"].astype(str).str.lower().map(SLA_DAYS)
    # A missing SLA (unknown level) is not counted as a breach.
    actionable["sla_breached"] = (actionable["detection_age_days"] > actionable["sla_days"]).fillna(False)
    general_hygiene_score = round(100 * (1 - actionable["sla_breached"].mean()), 2)

    def _safe_median(series: pd.Series) -> float:
        # All-NaN (e.g. code_age on non-secret groups) makes numpy warn
        # "Mean of empty slice"; return NaN quietly instead.
        values = series.dropna()
        return float(values.median()) if len(values) else float("nan")

    def _safe_quantile(series: pd.Series, q: float) -> float:
        values = series.dropna()
        return float(values.quantile(q)) if len(values) else float("nan")

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(actionable, dim)
        if key is None:
            continue
        for group, subset in actionable.groupby(key, dropna=True):
            breached = int(subset["sla_breached"].sum())
            rows.append({
                "snapshot_date": snapshot,
                "metric": "vulnerability_age",
                "dimension": dim,
                "group": group,
                "general_hygiene_score": general_hygiene_score,
                "detection_age_days": _safe_median(subset["detection_age_days"]),
                "detection_age_days_p90": _safe_quantile(subset["detection_age_days"], 0.9),
                # Secrets only; blank (NaN) when the group has none. Never mixed with detection age.
                "code_age_days": _safe_median(subset["code_age_days"]),
                "code_age_n": int(subset["code_age_days"].notna().sum()),
                "sla_breached_count": breached,
                "hygiene_score": round(100 * (1 - breached / len(subset)), 2),
                "n": int(len(subset)),
                "status": "READY",
                "note": "SLA_DAYS are placeholders; detection age counts from first Cycode scan"
                + ("; low n" if len(subset) < MIN_N else ""),
            })
    return pd.DataFrame(rows)

def metric_ai_leverage(
    violations_df: pd.DataFrame,
    audits_df: pd.DataFrame | None = None,
    reachability_df: pd.DataFrame | None = None,
) -> pd.DataFrame:
    """
    M6. AI leverage: % AI-verified / auto-triaged / reachability-confirmed.

    Definitions (report separately, never merged into one percentage):
      ai_verified_pct   : "Verified by AI" tag / secret findings. The tag
                          only exists on SecretDetection rows, so secrets
                          are the denominator, not all findings.
      auto_triage_pct   : audit-log Detection "Modified" events made by a
                          service account / all Detection "Modified" events
                          (112 of 143 in the sample audit log).
      reachability_pct  : findings with reachability confirmed by Stage 2
                          (vuln_intelligence_pipeline ReachabilityStatus) /
                          findings analysed.
      filtered_by_ai_context: findings tagged test file or not in latest
                          code, i.e. de-prioritised with context.
    Data: ai_verified_pct READY; auto_triage_pct needs audit logs;
    reachability needs a join to the pipeline's entity output. PARTIAL.

    PSEUDOCODE
        secrets = df[Violation category == "SecretDetection"]
        ai_verified_pct  = secrets.tag_ai_verified.mean()
        auto_triage_pct  = audits[(Resource Type == "Detection") &
                                  (Action == "Modified")]
                           .groupby(User == "Service Account").size() share
        reachability_pct = join(df, reachability_df, on=finding_key)
                           .reachability == "reachable" / analysed
        per dimension where a repo/project can be attributed (audit logs
        have no repo, so auto_triage_pct is org-level only; say so).
    """
    if violations_df.empty:
        return pd.DataFrame()
    snapshot = violations_df["snapshot_ts"].iloc[0]  # one value, not the whole column
    # Issue-level view next to the row-level one (repeats of an issue collapse to
    # one). Needs triage_tier/risk_score; without them these columns stay blank.
    try:
        reduced = reduce_noise_repetitive_violations(violations_df)
    except KeyError:
        reduced = None

    # Org-level values: audit events and reachability results carry no
    # project/team, so the same number is repeated on every row. Blank (NaN)
    # when the input is not supplied, never an error.
    auto_triage_pct = float("nan")
    if audits_df is not None and not audits_df.empty:
        changes = audits_df[audits_df["resource_type"].eq("Detection") & audits_df["action"].eq("Modified")]
        if len(changes):
            auto_triage_pct = round(100 * changes["user"].eq("Service Account").mean(), 2)
    reachability_pct = float("nan")
    if reachability_df is not None and not reachability_df.empty:
        reachability_pct = round(100 * reachability_df["reachability"].eq("reachable").mean(), 2)

    def _ai_pct(frame: pd.DataFrame) -> float:
        # The AI-verified tag exists only on secrets, so secrets are the denominator.
        secrets = frame[frame["violation_category"].eq("SecretDetection")]
        return round(100 * secrets["tag_ai_verified"].mean(), 2) if len(secrets) else float("nan")

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(violations_df, dim)
        if key is None:
            continue
        reduced_key = _dimension_series(reduced, dim) if reduced is not None else None
        for group, subset in violations_df.groupby(key, dropna=True):
            issues = reduced[reduced_key == group] if reduced is not None else None
            rows.append({
                "snapshot_date": snapshot,
                "metric": "ai_leverage",
                "dimension": dim,
                "group": group,
                "ai_verified_pct": _ai_pct(subset),
                "ai_verified_pct_issues": _ai_pct(issues) if issues is not None else float("nan"),
                "auto_triage_pct": auto_triage_pct,
                "reachability_pct": reachability_pct,
                # Count of findings tagged "Test file" (de-prioritised with context).
                "filtered_by_ai_context": int(subset["tag_test_file"].sum()),
                "filtered_by_ai_context_issues": int(issues["tag_test_file"].sum()) if issues is not None else float("nan"),
                "issues": len(issues) if issues is not None else float("nan"),
                "n": int(len(subset)),
                "status": "PARTIAL",
            })
    return pd.DataFrame(rows)

def metric_scanner_coverage(
    product_map_df: pd.DataFrame,
    repo_inventory_df: pd.DataFrame | None = None,
    snapshot_date: str | None = None,
    findings_repos: "set[str] | list[str] | None" = None,
) -> pd.DataFrame:
    """
    M7. Scanner coverage: % of repos and products scanned, by source.

    Definition: repos with scanning enabled (appearing in the inventory)
    divided by repos expected for the product, grouped by Source (GitHub,
    GitHub Advanced Security CodeQL, AWS) and by Project.
    Why: a clean backlog means nothing if the repo is not scanned.
    Data: the violations export only lists repos that HAVE findings, so
    use the "By repository" export (it includes Total Violations, incl. 0)
    plus product_map.csv for the expected repos. PARTIAL until both are
    loaded. In the 06-Oct data only 12 of the 19 repos in product_map.csv are
    present in the Cycode export.

    CURRENT DEFINITION (agreed): a repo is scanned if it is in the By-repository
    inventory OR has any finding in the violations exports (findings_repos).
    Expected = mapped repos that Cycode knows about (scanned). Mapped repos Cycode
    has never reported are listed in not_onboarded_repos instead of lowering the
    percentage, and scanned repos missing from the map are listed in
    unmapped_scanned_repos (org-level, on every row). So 100% means every repo
    Cycode scans is mapped to a product; a product with no repos in Cycode
    shows no percentage.

    PSEUDOCODE (original design)
        expected = product_map.csv (repo, product, in_cycode flag)
        scanned  = repo_inventory_df where Source == "GitHub" (etc.)
        coverage[project] = |expected ∩ scanned| / |expected|
        by_source[project, source] = repos with at least one scan of source
        list missing repos explicitly (they are the action item)
        dedupe repos that appear twice (CodeQL source / blank organisation)
    """
    # Expected repos: every repo in the product map, once, whatever its
    # in_cycode flag says (that flag only records what was exported on one day).
    expected = product_map_df[["repo", "product_line"]].dropna(subset=["repo"]).drop_duplicates("repo").copy()
    # "Loop (assumed)" and "Loop" are the same product; the suffix only marks an unconfirmed mapping.
    expected["product_line"] = expected["product_line"].astype(str).str.replace(
        r"\s*\(assumed\)\s*$", "", regex=True
    )

    scanned = set()
    if repo_inventory_df is not None and not repo_inventory_df.empty:
        # The By-repository export lists some repos twice (CodeQL source, blank
        # organisation); reduce to the repo name and count each once.
        scanned |= set(repo_inventory_df["Repository Name"].map(_repo_slug).dropna())
    if findings_repos is not None:
        scanned |= {_repo_slug(r) for r in findings_repos if _repo_slug(r)}
    blocked = not scanned  # neither an inventory nor any findings: nothing to show
    status = "BLOCKED" if blocked else "PARTIAL"
    expected["scanned"] = expected["repo"].isin(scanned)
    unmapped = ", ".join(sorted(scanned - set(expected["repo"])))

    onboarded = expected[expected["scanned"]]
    general_coverage_pct = float("nan") if blocked or onboarded.empty else 100.0

    rows = []
    for product, subset in expected.groupby("product_line"):
        in_cycode = subset[subset["scanned"]]
        expected_repos = len(in_cycode)
        rows.append({
            # No snapshot date exists in either input; pass the export date in.
            "snapshot_date": snapshot_date,
            "metric": "scanner_coverage",
            "dimension": "Project",
            "group": product,
            "general_coverage_pct": general_coverage_pct,
            "coverage_pct": float("nan") if blocked or not expected_repos else 100.0,
            "expected_repos": expected_repos,
            "scanned_repos": expected_repos,
            "not_onboarded_repos": ", ".join(sorted(subset.loc[~subset["scanned"], "repo"])),
            "unmapped_scanned_repos": unmapped,
            "n": expected_repos,
            "status": status,
        })
    return pd.DataFrame(rows)

# Annual platform-wide AI spend in USD. PLACEHOLDER: replace with the real
# figure (or per-product spend) once it is known; it is passed in, not hard-wired
# into the metric, so nothing else has to change.
AI_COST_PLACEHOLDER_USD = 140_000

# period label -> (pandas period code, periods per year)
_COST_PERIODS = {"week": ("W", 52), "month": ("M", 12), "quarter": ("Q", 4)}

def _avg_per_period(closing_times: pd.Series, freq: str) -> float:
    """
    Mean number of closings per calendar period, from the first to the last
    period that has one. Periods in between with no closing count as zero, so a
    quiet week lowers the average instead of being skipped.
    """
    periods = closing_times.dt.tz_convert("UTC").dt.tz_localize(None).dt.to_period(freq)
    counts = periods.value_counts()
    span = pd.period_range(periods.min(), periods.max())
    return float(counts.reindex(span, fill_value=0).mean())

def metric_remediations_vs_ai_cost(
    resolved_df: pd.DataFrame,
    annual_ai_cost: float = AI_COST_PLACEHOLDER_USD,
) -> pd.DataFrame:
    """
    M8. Average remediations per week / month / quarter vs. AI cost.

    A remediation is a Fixed, Resolved ISSUE with a known closing time (the
    same rule as MTTR): repeated rows of one issue count once. Pass the linked frame from add_resolution_columns().
    The AI cost is a platform figure, so every dimension splits it between its
    groups and the shares always add up to the platform cost for the period.

    Per row (dimension, group, period):
      cost                  the group's share of annual_ai_cost / periods-per-year
      cost_share_pct        that share
      remediations          total fixes in the data
      avg_remediations      mean fixes per period (see _avg_per_period)
      cost_per_remediation  cost / avg_remediations (NaN when the group fixed nothing)
      general_cost_per_remediation  the same ratio for the whole platform

    Cost split: PLACEHOLDER rule, in proportion to the number of findings the
    group has in the frame passed in. The metric is only as meaningful as that
    driver; agree on a real one (triage volume, AI actions per product) before
    comparing groups. Splitting by remediations would make every group's
    ratio identical, so that is deliberately not used.
    Data: PARTIAL until the real AI spend is known (see AI_COST_PLACEHOLDER_USD).
    Note: the qmd asks for "AI cost as a percentage"; confirm the denominator.
    """
    if resolved_df.empty:
        return pd.DataFrame()
    required = {"status_raw", "resolved_at", "resolved_at_source", "resolution_reason", "snapshot_ts"}
    missing = required - set(resolved_df.columns)
    if missing:
        raise ValueError(f"run add_resolution_columns() first; missing {sorted(missing)}")
    snapshot = resolved_df["snapshot_ts"].iloc[0]  # one value, not the whole column

    # A remediation is one fixed ISSUE (repeats merged, counted when its last
    # occurrence closed); the cost-split weights use distinct issues too.
    fixes = _fixed_issues(resolved_df)
    reduced_resolved_df = _dedup_by_issue(resolved_df)
    if fixes.empty:
        return pd.DataFrame()

    platform_avg = {
        period: _avg_per_period(fixes["resolved_at"], freq)
        for period, (freq, _) in _COST_PERIODS.items()
    }

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(reduced_resolved_df, dim)
        if key is None:
            continue
        weights = reduced_resolved_df.groupby(key, dropna=True).size()
        shares = weights / weights.sum()
        fix_key = _dimension_series(fixes, dim)
        for group, share in shares.items():
            group_fixes = fixes[fix_key == group]
            for period, (freq, per_year) in _COST_PERIODS.items():
                platform_cost = annual_ai_cost / per_year
                cost = platform_cost * share
                avg = _avg_per_period(group_fixes["resolved_at"], freq) if len(group_fixes) else 0.0
                rows.append({
                    "snapshot_date": snapshot,
                    "metric": "remediations_vs_ai_cost",
                    "dimension": dim,
                    "group": group,
                    "period": period,
                    "cost": cost,
                    "cost_share_pct": round(100 * share, 2),
                    "remediations": int(len(group_fixes)),
                    "avg_remediations": avg,
                    "cost_per_remediation": cost / avg if avg > 0 else float("nan"),
                    "general_cost_per_remediation": platform_cost / platform_avg[period],
                    "n": int(weights[group]),
                    "status": "PARTIAL",
                    "note": f"AI cost is a {annual_ai_cost:,.0f}/year placeholder split by findings volume",
                })
    return pd.DataFrame(rows)

def metric_risk_posture_score(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    M9. Risk posture score per Project / Team / Repository (0-100, higher is better).

    One open finding contributes

        exposure = level weight * (risk score / 100) * tier multiplier

    using POSTURE_LEVEL_WEIGHT and POSTURE_TIER_MULTIPLIER. Noise contributes
    nothing, and a resolved finding contributes nothing. A group's raw exposure
    is the sum, so a larger backlog scores worse than one finding of the same
    average severity. Dividing by the number of repositories in the group keeps
    a product with more repos from looking worse only because it is larger.

    The score is 100 / (1 + norm / K), where K is the median normalized
    exposure of the groups in that same dimension. A group at the median
    scores 50, no exposure scores 100, and the score falls gradually (it never
    hits 0), so very large backlogs still rank against each other. K = 0 means
    nobody has open exposure, and every group scores 100.

    Age, MTTR, and scanner coverage stay out of this number. Age is already
    the hygiene metric, and on these exports it mostly measures time since the
    first scan. MTTR and coverage are not ready every week, so folding them in
    would move the score when an input is missing. Show raw_exposure next to
    the score, and top_policies names the three policies that produced it.
    """
    if violations_df.empty:
        return pd.DataFrame()
    reduced_violations_df = reduce_noise_repetitive_violations(violations_df)
    status_column = "status_raw" if "status_raw" in reduced_violations_df.columns else "status"
    if status_column not in reduced_violations_df.columns:
        return pd.DataFrame()
    status = reduced_violations_df[status_column].map(
        lambda value: str(getattr(value, "value", value)).lower()
    )
    open_findings = reduced_violations_df.loc[status.eq("open")].copy()
    if open_findings.empty:
        return pd.DataFrame()

    snapshot = reduced_violations_df["snapshot_ts"].iloc[0]
    risk = pd.to_numeric(open_findings["risk_score"], errors="coerce").fillna(0).clip(0, 100) / 100
    level = open_findings["risk_level"].astype(str).str.lower().map(POSTURE_LEVEL_WEIGHT).fillna(0)
    tier = open_findings["triage_tier"].map(POSTURE_TIER_MULTIPLIER).fillna(0)
    open_findings["exposure"] = level * risk * tier

    rows = []
    for dim in DIMENSIONS:
        key = _dimension_series(open_findings, dim)
        if key is None:
            continue
        grouped = []
        for group, subset in open_findings.groupby(key, dropna=True):
            raw = float(subset["exposure"].sum())
            repo_column = "repository" if "repository" in subset.columns else "Repository"
            repos = int(subset[repo_column].map(_repo_slug).nunique()) if repo_column in subset.columns else 1
            repos = max(repos, 1)
            by_policy = subset.groupby(subset["policy"].fillna("(no policy)"))["exposure"].sum()
            by_policy = by_policy[by_policy > 0].sort_values(ascending=False).head(3)
            grouped.append((group, subset, raw, repos, raw / repos, ", ".join(by_policy.index)))
        scale = float(np.median([item[4] for item in grouped])) if grouped else 0.0
        for group, subset, raw, repos, norm, top in grouped:
            score = 100 if scale == 0 else int(round(100 / (1 + norm / scale)))
            rows.append({
                "snapshot_date": snapshot,
                "metric": "risk_posture_score",
                "dimension": dim,
                "group": group,
                "posture_score": score,
                "value": score,
                "raw_exposure": raw,
                "norm_exposure": norm,
                "repos": repos,
                "top_policies": top,
                "n": int(len(subset)),
                "status": "READY" if int(len(subset)) >= MIN_N else "PARTIAL",
                "note": "score = 100 / (1 + exposure per repo / median exposure per repo); 50 = typical group",
            })
    return pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# Presentation layer: one row per group, every metric side by side
# ---------------------------------------------------------------------------
SUMMARY_COLUMNS = [
    "M1 Actionable High/Crit open",
    "M3 MTTR Critical (median days)",
    "M3 MTTR High (median days)",
    "M4 Noise rate (%)",
    "M5 Median detection age (days)",
    "M5 SLA breaches",
    "M5 Hygiene score (0-100)",
    "M6 AI-verified (% of secrets)",
    "M7 Scanner coverage (%)",
    "M8 AI cost per remediation (USD, monthly)",
    "M9 Posture score (0-100)",
]

SUMMARY_FOOTNOTES = [
    "Units: 'Open findings' and the M4 rate are Cycode ROWS (one per occurrence). 'Open issues (distinct)' and "
    "M1, M5, M6, M9 count DISTINCT ISSUES (repeats of the same secret/CVE+package/location merged); "
    "M3 and M8 count fixed issues. Compare rows with issues only knowingly.",
    "M1: distinct open issues that are High/Critical risk, score >= 70, severity >= Medium.",
    "M3: issues Cycode closed as 'Fixed' (linked via the audit log), earliest detection to last occurrence closed; "
    "blank = no data. Loop is skewed by bulk CI/CD closures.",
    "M4: share of distinct open ISSUES that are Noise (Low/Info and score < 30); the row-level rate is in the M4 detail.",
    "M5: per distinct actionable issue; age counts from first Cycode scan (initial scan 26-Aug); SLA days are placeholders.",
    "M6: AI-verified share is secrets only (row and issue versions in the M6 detail); auto-triage/reachability are org-level and blank until actor IDs are mapped.",
    "M7: Project view only. 100% = every repo Cycode scans is in product_map.csv; mapped repos Cycode has never reported are listed as not_onboarded_repos.",
    "M8: remediations = fixed issues; AI cost is a 140,000/year PLACEHOLDER split by distinct-issue volume.",
    "M9: exposure summed per distinct issue; 100 / (1 + exposure per repo / median exposure per repo); 50 = typical group, relative not absolute.",
]

def _pick(df: pd.DataFrame, dimension: str, column: str, **filters) -> pd.Series:
    """Return `column` indexed by group for one dimension (empty if unavailable)."""
    empty = pd.Series(dtype=float)
    if df is None or df.empty or "dimension" not in df or column not in df:
        return empty
    sub = df[df["dimension"] == dimension]
    for key, val in filters.items():
        if key not in sub:
            return empty
        sub = sub[sub[key] == val]
    return sub.drop_duplicates("group").set_index("group")[column]

def build_metric_summary(metrics: dict, dimension: str = "Project") -> pd.DataFrame:
    """
    One meeting-ready table for a dimension: rows = groups, columns = metrics.

    metrics: {"M1": df, "M3": df, ...} as returned by the metric_* functions.
    Missing metrics become blank columns, never errors. Values are rounded and
    column names carry the metric id and unit so the table explains itself.
    """
    if dimension not in DIMENSIONS:
        raise ValueError(f"dimension must be one of {DIMENSIONS}")
    m = lambda k: metrics.get(k)
    cols = {
        "M1 Actionable High/Crit open": _pick(m("M1"), dimension, "value"),
        "M3 MTTR Critical (median days)": _pick(m("M3"), dimension, "ttr_days_median", severity="Critical"),
        "M3 MTTR High (median days)": _pick(m("M3"), dimension, "ttr_days_median", severity="High"),
        "M4 Noise rate (%)": _pick(m("M4"), dimension, "noise_rate_issues"),
        "M5 Median detection age (days)": _pick(m("M5"), dimension, "detection_age_days"),
        "M5 SLA breaches": _pick(m("M5"), dimension, "sla_breached_count"),
        "M5 Hygiene score (0-100)": _pick(m("M5"), dimension, "hygiene_score"),
        "M6 AI-verified (% of secrets)": _pick(m("M6"), dimension, "ai_verified_pct"),
        "M7 Scanner coverage (%)": _pick(m("M7"), dimension, "coverage_pct"),
        "M8 AI cost per remediation (USD, monthly)": _pick(m("M8"), dimension, "cost_per_remediation", period="month"),
        "M9 Posture score (0-100)": _pick(m("M9"), dimension, "posture_score"),
    }
    out = pd.DataFrame(cols)
    # Open-finding volume gives context for every other number.
    total = _pick(m("M4"), dimension, "total")
    out.insert(0, "Open findings", total)
    # Rows vs distinct issues: M1, M5, M6, M9 (and M3/M8 for closed work) count issues.
    out.insert(1, "Open issues (distinct)", _pick(m("M4"), dimension, "issues"))
    out = out.reindex(columns=["Open findings", "Open issues (distinct)"] + SUMMARY_COLUMNS)
    for c in out.columns:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    out = out.round(1)
    # Sort so the biggest backlog (the likely discussion topic) is first.
    out = out.sort_values("Open findings", ascending=False, na_position="last")
    out.index.name = dimension
    return out

def format_metric_summary(summary: pd.DataFrame) -> str:
    """Plain-text rendering: blanks as '-', integers without decimals."""
    def fmt(v):
        if pd.isna(v):
            return "-"
        return f"{int(v):,}" if float(v).is_integer() else f"{v:,.1f}"
    shown = summary.apply(lambda col: col.map(fmt))
    return shown.to_string()

def print_metric_summaries(metrics: dict) -> None:
    """Print every dimension's summary followed by the footnotes."""
    for dim in DIMENSIONS:
        print(f"\n=== Security scorecard by {dim} ===")
        print(format_metric_summary(build_metric_summary(metrics, dim)))
    print("\nNotes:")
    for line in SUMMARY_FOOTNOTES:
        print(" -", line)

METRIC_SPECS = [
    {"id": "M1", "name": "actionable_open_high_critical"},
    {"id": "M2", "name": "backlog_trend"},
    {"id": "M3", "name": "mttr_by_severity"},
    {"id": "M4", "name": "noise_reduction"},
    {"id": "M5", "name": "vulnerability_age"},
    {"id": "M6", "name": "ai_leverage"},
    {"id": "M7", "name": "scanner_coverage"},
    {"id": "M8", "name": "remediations_vs_ai_cost"},
    {"id": "M9", "name": "risk_posture_score"},
]

def compute_all_metrics(
    all_df: pd.DataFrame,
    previous_df: pd.DataFrame | None = None,
    product_map_df: pd.DataFrame | None = None,
    repo_inventory_df: pd.DataFrame | None = None,
    snapshot_date: str | None = None,
    annual_ai_cost: float = AI_COST_PLACEHOLDER_USD,
) -> dict:
    """
    Run M1-M9 and return {"M1": frame, ...}.

    all_df must be the merged open+closed frame after add_resolution_columns,
    add_triage_and_age and the project/team mapping. Open-backlog metrics
    (M1, M2, M4, M5, M6, M9) use only rows whose Cycode status is Open;
    M3 and M8 use the full frame (they need Resolved rows).
    A metric that cannot run is recorded as a BLOCKED row with the reason,
    never silently dropped.
    """
    open_df = all_df[all_df["status_raw"].eq("Open")]
    previous_open_df = (
        previous_df[previous_df["status_raw"].eq("Open")]
        if previous_df is not None and not previous_df.empty
        else None
    )
    snapshot_date = snapshot_date or str(all_df["snapshot_ts"].iloc[0])[:10]

    def blocked(spec, reason):
        return pd.DataFrame([{"snapshot_date": snapshot_date, "metric": spec["name"],
                              "status": "BLOCKED", "note": reason}])

    runners = {
        "M1": lambda: metric_actionable_open_high_critical(open_df),
        "M2": lambda: metric_backlog_trend(open_df, previous_open_df),
        "M3": lambda: metric_mttr_by_severity(all_df),
        "M4": lambda: metric_noise_reduction(open_df),
        "M5": lambda: metric_vulnerability_age(open_df),
        "M6": lambda: metric_ai_leverage(open_df),
        "M7": lambda: metric_scanner_coverage(product_map_df, repo_inventory_df, snapshot_date, set(all_df["repository"].dropna())),
        "M8": lambda: metric_remediations_vs_ai_cost(all_df, annual_ai_cost),
        "M9": lambda: metric_risk_posture_score(open_df),
    }
    results = {}
    for spec in METRIC_SPECS:
        if spec["id"] == "M7" and product_map_df is None:
            results["M7"] = blocked(spec, "needs product_map.csv")
            continue
        try:
            results[spec["id"]] = runners[spec["id"]]()
        except Exception as exc:  # one failing metric must not hide the others
            warnings.warn(f"{spec['id']} failed: {exc}")
            results[spec["id"]] = blocked(spec, f"error: {exc}")
    return results

def run_report(
    folder: str | Path,
    date_label: str,
    product_map_path: str | Path = "product_map.csv",
    inventory_path: str | Path | None = None,
    out_dir: str | Path = "reports",
) -> dict:
    """
    End to end: load exports -> link audit -> tier/age -> map -> M1-M9 -> scorecards.

    Expects in `folder` (date_label like "15-Oct-2026"):
        Cycode - All violations - <date>.csv
        Cycode - All violations (closed) - <date>.csv
        Cycode - Audit Logs - <date>.csv
    Writes ONE file, <out_dir>/cycode_metrics_<date>.csv: scorecards, notes,
    M1-M9 detail and extras X1-X8 stacked as sections. Each section starts with
    a "## <name>" line, then its header and rows, then a blank line.
    Returns {"metrics", "summaries", "extras"}.
    """
    folder, out_dir = Path(folder), Path(out_dir)
    snapshot_ts = datetime.strptime(date_label, "%d-%b-%Y").strftime("%Y-%m-%dT00:00:00Z")
    all_df = load_all_violations(
        {
            "open": str(folder / f"Cycode - All violations - {date_label}.csv"),
            "closed": str(folder / f"Cycode - All violations (closed) - {date_label}.csv"),
        },
        snapshot_ts,
        f"{folder} / Cycode - All violations - {date_label}.csv",
        f"{folder}_api / Cycode - All violations (closed) - {date_label}.csv",
    )
    previous_date_label = (datetime.strptime(date_label, "%d-%b-%Y") - timedelta(days=7)).strftime("%d-%b-%Y")
    previous_folder = folder.parent / previous_date_label
    previous_snapshot_ts = datetime.strptime(previous_date_label, "%d-%b-%Y").strftime("%Y-%m-%dT00:00:00Z")
    previous_df = None
    if previous_folder.is_dir():
        try:
            previous_df = load_all_violations(
                {
                    "open": str(previous_folder / f"Cycode - All violations - {previous_date_label}.csv"),
                    "closed": str(previous_folder / f"Cycode - All violations (closed) - {previous_date_label}.csv"),
                },
                previous_snapshot_ts,
                f"{previous_folder} / Cycode - All violations - {previous_date_label}.csv",
                f"{previous_folder}_api / Cycode - All violations (closed) - {previous_date_label}.csv",
            )
        except FileNotFoundError:
            warnings.warn(f"previous snapshot {previous_date_label} incomplete; M2 will be PARTIAL")
    events_df = load_audit_detection_events(str(folder / f"Cycode - Audit Logs - {date_label}.csv"))
    all_df = add_resolution_columns(all_df, events_df)
    for message in audit_coverage_warnings(all_df, events_df):
        warnings.warn(message)
    all_df = add_triage_and_age(all_df)
    # One product map file drives project, team and scanner coverage (M7).
    product_map = load_product_map(product_map_path) if Path(product_map_path).exists() else None
    # Pull any violation repos missing from the map into product_map.csv as
    # TO CONFIRM rows (suggestions filled; product_line stays Unmapped until confirmed).
    if product_map is not None:
        slugs = all_df[_repository_column(all_df)].map(_repo_slug).dropna().unique()
        product_map, added = add_missing_repos_to_product_map(
            product_map, slugs, date_label, apply_suggestions=False
        )
        if added:
            write_product_map(product_map, product_map_path)
            warnings.warn(
                f"Added {len(added)} new repo(s) to {Path(product_map_path).name} as TO CONFIRM "
                f"({', '.join(added[:8])}{'...' if len(added) > 8 else ''}). "
                f"Set product_line/team (or re-run with suggested values confirmed)."
            )
    all_df = map_repository_to_team(map_repository_to_project(all_df, product_map), product_map)
    if previous_df is not None and not previous_df.empty:
        # Same maps so M2 can attribute new/resolved to Project / Team / Repository.
        previous_df = map_repository_to_team(map_repository_to_project(previous_df, product_map), product_map)
    unmapped = unmapped_repositories(all_df)
    if len(unmapped):
        warnings.warn(
            f"{len(unmapped)} repositories still have product_line=Unmapped "
            f"({', '.join(f'{r} ({n:,} rows)' for r, n in unmapped.head(8).items())}"
            f"{'...' if len(unmapped) > 8 else ''}). Confirm them in the product map."
        )
    inventory_file = resolve_repository_inventory(inventory_path, date_label)
    inventory = pd.read_csv(inventory_file) if inventory_file is not None else None
    if inventory is None:
        warnings.warn("no By-repository export found under data/; M7 will be BLOCKED")
    metrics = compute_all_metrics(all_df, previous_df, product_map, inventory, snapshot_ts[:10])
    summaries = {dim: build_metric_summary(metrics, dim) for dim in DIMENSIONS}

    # Extra metrics X1-X8 (open backlog only; X8 is org-level from the audit log)
    open_df = add_issue_key(all_df[all_df["status_raw"].eq("Open")])
    extras = {}
    for dim in ("Project", "Team"):
        extras[f"X1-X6 by {dim}"] = summarize_extra_metrics(open_df, dim)
    extras["X7 actionable by category"] = actionable_mix_by_category(open_df, "Project")
    extras["X9 noise after dedup by Project"] = summarize_noise_after_dedup(open_df, "Project")
    extras["X9 noise after dedup by Team"] = summarize_noise_after_dedup(open_df, "Team")
    extras["X10 tuning by Project"] = summarize_tuning(open_df, "Project")
    extras["X10 tuning by Team"] = summarize_tuning(open_df, "Team")
    extras["X11 exclusion candidates"] = noise_exclusion_candidates(open_df)
    try:
        life = issue_lifecycle(all_df)
        extras["X14 daily flow"] = daily_issue_flow(all_df, None, life)
        extras["X14 daily flow by Project"] = daily_issue_flow(all_df, "Project", life)
        sla_scored = predict_sla_risk(all_df, life=life)
        extras["X15 SLA risk by Project"] = summarize_sla_risk(sla_scored, "Project")
        extras["X15 SLA risk by Team"] = summarize_sla_risk(sla_scored, "Team")
        extras["X16 SLA at-risk issues"] = sla_at_risk_list(sla_scored)
    except Exception as exc:  # the flow/SLA extras must not stop the report
        warnings.warn(f"X14-X16 failed: {exc}")
    try:
        audits_df = load_audits(str(folder / f"Cycode - Audit Logs - {date_label}.csv"), snapshot_ts)
        extras["X8 triage activity"] = summarize_triage_activity(audits_df)
    except Exception as exc:  # audit log shape problems must not stop the report
        warnings.warn(f"X8 failed: {exc}")

    sheets = {f"Scorecard {dim}": (table, True) for dim, table in summaries.items()}
    sheets["Notes"] = (pd.DataFrame({"Notes": SUMMARY_FOOTNOTES}), False)
    # sheets.update({f"{k} detail": (v, False) for k, v in metrics.items()})
    sheets.update({name: (table, True) for name, table in extras.items()})

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"cycode_metrics_{date_label}.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        for name, (table, keep_index) in sheets.items():
            fh.write(f"## {name}\n")
            table.to_csv(fh, index=keep_index)
            fh.write("\n")
    print_metric_summaries(metrics)
    for name, table in extras.items():
        print(f"\n=== {name} ===")
        print(table.to_string())
    print(f"\nWrote {path} ({len(sheets)} sections)")

    # Per-metric detail (severity splits, policies, periods...) lives in a
    # companion file so the main CSV stays presentable. The dashboard reads both.
    detail_path = out_dir / f"cycode_metrics_{date_label}_detail.csv"
    with open(detail_path, "w", newline="", encoding="utf-8-sig") as fh:
        for key, frame in metrics.items():
            fh.write(f"## {key} detail\n")
            frame.to_csv(fh, index=False)
            fh.write("\n")
    print(f"Wrote {detail_path} ({len(metrics)} metric detail sections)")
    return {"metrics": metrics, "summaries": summaries, "extras": extras}

# ---------------------------------------------------------------------------
# Weekly digest: history, week-over-week change, data-quality checks
# ---------------------------------------------------------------------------
HISTORY_FILE = "metrics_history.csv"
# Scorecard columns tracked week over week, and whether a rise is good.
DIGEST_METRICS = {
    "Open findings": None,
    "Open issues (distinct)": False,
    "M1 Actionable High/Crit open": False,
    "M4 Noise rate (%)": False,
    "M5 Hygiene score (0-100)": True,
    "M9 Posture score (0-100)": True,
}
ROW_COUNT_TOLERANCE = 0.5  # +/-50% vs the previous snapshot suggests the export filter changed

def history_from_summaries(summaries: dict, snapshot_date: str, total_rows: int) -> pd.DataFrame:
    """Long frame (snapshot_date, dimension, group, metric, value) of every scorecard cell."""
    parts = []
    for dim, table in summaries.items():
        if table is None or table.empty:
            continue
        long = table.rename_axis("group").reset_index().melt(
            id_vars="group", var_name="metric", value_name="value"
        )
        long.insert(0, "dimension", dim)
        parts.append(long)
    out = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(
        columns=["dimension", "group", "metric", "value"])
    out.insert(0, "snapshot_date", snapshot_date)
    # Export size is kept for the next week's filter-change check.
    total = pd.DataFrame([{"snapshot_date": snapshot_date, "dimension": "Org", "group": "TOTAL",
                           "metric": "_total_rows", "value": float(total_rows)}])
    return pd.concat([out, total], ignore_index=True)

def append_metrics_history(history_path: str | Path, new_rows: pd.DataFrame) -> pd.DataFrame:
    """
    Append to the history file. Rows for the same snapshot_date are replaced, so
    re-running a week is idempotent. Returns the full history.
    """
    history_path = Path(history_path)
    history_path.parent.mkdir(parents=True, exist_ok=True)
    if history_path.exists():
        old = pd.read_csv(history_path, dtype={"snapshot_date": str})
        old = old[~old["snapshot_date"].isin(new_rows["snapshot_date"].astype(str).unique())]
        full = pd.concat([old, new_rows], ignore_index=True)
    else:
        full = new_rows.copy()
    full = full.sort_values(["snapshot_date", "dimension", "group", "metric"], kind="mergesort")
    full.to_csv(history_path, index=False)
    return full

def validate_snapshot(history: pd.DataFrame, snapshot_date: str, summaries: dict) -> list[str]:
    """Data-quality warnings to read before trusting the week's numbers."""
    warns: list[str] = []
    totals = history[history["metric"] == "_total_rows"].set_index("snapshot_date")["value"]
    earlier = totals[totals.index < snapshot_date]
    if snapshot_date in totals.index and len(earlier):
        now, before = float(totals[snapshot_date]), float(earlier.iloc[-1])
        if before and abs(now - before) / before > ROW_COUNT_TOLERANCE:
            warns.append(
                f"Export size changed from {before:,.0f} to {now:,.0f} rows "
                f"({(now - before) / before:+.0%}); check that the export filters did not change "
                "(if they did, treat this week as a new baseline)."
            )
    project = summaries.get("Project")
    if project is not None and "Unmapped" in project.index and project.loc["Unmapped"].notna().any():
        warns.append("Some repositories are Unmapped; add them to the repo-to-project map.")
    return warns

def build_digest(history: pd.DataFrame, snapshot_date: str, dimension: str = "Project") -> pd.DataFrame:
    """
    Current vs previous snapshot for the headline metrics, per group.

    Columns: group, metric, previous, current, change, change_pct, direction
    (better / worse / flat / new, using DIGEST_METRICS for what "better" means).
    Sorted by the relative size of the move so "what changed since last week" reads top-down.
    """
    h = history[(history["dimension"] == dimension) & history["metric"].isin(DIGEST_METRICS)]
    dates = sorted(h["snapshot_date"].astype(str).unique())
    if snapshot_date not in dates:
        return pd.DataFrame()
    prior = [d for d in dates if d < snapshot_date]
    cur = h[h["snapshot_date"].astype(str) == snapshot_date].set_index(["group", "metric"])["value"]
    prev = (h[h["snapshot_date"].astype(str) == prior[-1]].set_index(["group", "metric"])["value"]
            if prior else pd.Series(dtype=float))
    out = pd.DataFrame({"previous": prev, "current": cur})
    out.index.names = ["group", "metric"]  # names are lost when there is no previous snapshot
    out = out.reset_index()
    out["change"] = out["current"] - out["previous"]
    # Relative move, so metrics in different units (counts, 0-100 scores) rank fairly.
    out["change_pct"] = (100 * out["change"] / out["previous"].abs().where(out["previous"] != 0)).round(1)

    def direction(row) -> str:
        if pd.isna(row["current"]):
            return "no data"
        if pd.isna(row["previous"]):
            return "new"
        if row["change"] == 0:
            return "flat"
        good_up = DIGEST_METRICS[row["metric"]]
        if good_up is None:
            return "up" if row["change"] > 0 else "down"
        return "better" if (row["change"] > 0) == good_up else "worse"

    out["direction"] = out.apply(direction, axis=1)
    out = out[out["direction"] != "no data"]  # groups with nothing to report are noise in a digest
    # A move away from a zero baseline has no percentage; rank it first.
    out["_size"] = out["change_pct"].abs().fillna(out["change"].abs().gt(0).astype(float) * 1e9)
    out["_size"] = out["_size"].where(out["change"].notna(), -1)
    return out.sort_values("_size", ascending=False).drop(columns="_size").reset_index(drop=True)

def fetch_audits_to(folder: str | Path, date_label: str, start: str = "2026-08-01T00:00:00Z") -> Path:
    """
    Download the audit log through the Cycode API into the export folder under
    the standard file name. Credentials come from .env (never printed). Violations
    still come from the Cycode UI export, which is the proven, filter-controlled path.
    """
    import csv as _csv
    import fetch_audit_logs as fal  # sibling script

    end = datetime.strptime(date_label, "%d-%b-%Y").strftime("%Y-%m-%dT23:59:59Z")
    token = fal.access_token(fal.load_env(fal.ENV_PATH))
    rows = fal.fetch_audit_logs(token, start=start, end=end)
    path = Path(folder) / f"Cycode - Audit Logs - {date_label}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = _csv.DictWriter(handle, fieldnames=fal.CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path

def run_weekly_digest(
    date_label: str,
    folder: str | Path | None = None,
    state_dir: str | Path = "state",
    product_map_path: str | Path = "../product_map.csv",
    inventory_path: str | Path | None = None,
    fetch_audits: bool = False,
    fetch_violations: bool = False,
) -> dict:
    """
    Weekly job: one run per new Cycode export (same filters every week).

    Put the open and closed violation exports for <date_label> in `folder`
    (default ./<date_label>), or let the API provide them:
      fetch_violations=True  download ALL violations (every status, whole
                             history) with fetch_violations.py. The API returns the
                             current state, so this is a full snapshot of the day
                             it runs and cannot be back-dated.
      fetch_audits=True      download the audit log (from 2026-08-01, before the first scan, to the date).
    Anything not fetched must already be in the folder.

    Steps: (optional audit fetch) -> run_report (all metrics, scorecards, CSVs
    in state_dir/reports) -> append scorecards to state_dir/metrics_history.csv
    (same snapshot_date replaced, so reruns are idempotent) -> data-quality
    warnings -> week-over-week digest per Project.

    Returns {"metrics", "summaries", "extras", "history", "digest", "warnings"}
    and writes state_dir/reports/digest_<date>.csv. If filters change, the row
    count warning fires: treat that week as a new baseline.
    """
    folder = Path(folder) if folder else Path(date_label)
    state_dir = Path(state_dir)
    if fetch_violations:
        import fetch_violations as fv  # sibling script
        token = fv.fal.access_token(fv.fal.load_env(fv.fal.ENV_PATH))
        fv.write_exports(folder, date_label, fv.fetch_all(token))
    if fetch_audits:
        print(f"Wrote {fetch_audits_to(folder, date_label)}")
    inventory = inventory_path or str(
        Path("~/Documents/Cycode Project/data").expanduser()
        / f"Cycode - By repository - {date_label}.csv"
    )
    report = run_report(folder, date_label, product_map_path, inventory, state_dir / "reports")

    snapshot_date = datetime.strptime(date_label, "%d-%b-%Y").strftime("%Y-%m-%d")
    total_rows = int(report["summaries"]["Project"]["Open findings"].sum())
    history = append_metrics_history(
        state_dir / HISTORY_FILE,
        history_from_summaries(report["summaries"], snapshot_date, total_rows),
    )
    warns = validate_snapshot(history, snapshot_date, report["summaries"])
    digest = build_digest(history, snapshot_date, "Project")
    digest_path = state_dir / "reports" / f"digest_{date_label}.csv"
    digest.to_csv(digest_path, index=False)

    # The same insights the dashboard popup shows, from the stored history (this week vs the last stored week).
    def _card(date: str, dim: str) -> pd.DataFrame:
        part = history[(history["dimension"] == dim) & (history["snapshot_date"].astype(str) == date)
                       & (history["metric"] != "_total_rows")]
        return part.pivot_table(index="group", columns="metric", values="value", aggfunc="first")
    earlier = sorted(d for d in history["snapshot_date"].astype(str).unique() if d < snapshot_date)
    anomalies = identify_anomalies(_card(snapshot_date, "Project"), _card(earlier[-1], "Project") if earlier else None,
                                   "Project", history, snapshot_date)
    insights = attain_insights(anomalies)

    print("\n=== Insights (this week vs the last stored week) ===")
    for line in insights:
        print(" -", line)
    print("\n=== Weekly digest (Project) ===")
    print(digest.head(15).to_string(index=False) if not digest.empty else "no data")
    blocked = [k for k, v in report["metrics"].items() if "status" in v and (v["status"] == "BLOCKED").all()]
    if blocked:
        warns.append(f"Blocked metrics this week: {', '.join(blocked)}")
    for w in warns:
        print("WARNING:", w)
    print(f"Wrote {digest_path} and {state_dir / HISTORY_FILE}")
    return {**report, "history": history, "digest": digest, "warnings": warns, "anomalies": anomalies, "insights": insights}

# =============================================================================
# ADDITIONAL METRICS (implemented; work on a single snapshot)
# =============================================================================
# These complement M1-M9 and need nothing beyond the violations export (plus
# the audit log for X8). Run them on frames that went through
# add_triage_and_age() and the project/team mapping.
#
#   X1 unique issues vs rows        - real workload behind the row count
#   X2 fix-available rate (SCA)     - how much of the SCA backlog is a version bump
#   X3 live-secret exposure         - actionable secrets in current, non-test code
#   X4 test-file share              - noise that tags already identify
#   X5 ownership coverage           - findings that name a person (ticket/assignee
#                                     are 0% populated, so this is the best proxy)
#   X6 policy concentration         - share of findings from the top 5 policies
#   X7 actionable mix by category   - where the actionable work sits
#   X8 triage activity (audit log)  - weekly volume and automation share

def add_issue_key(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add issue_key: one value per underlying issue rather than per row.

    Cycode creates one row per occurrence, so one leaked secret in many files
    or one CVE in many manifests inflates the row count.
      SecretDetection : repository + secret SHA (identifier)
      SCA             : repository + CVE (identifier) + package
      everything else : repository + policy + file + line
    """
    out = violations_df.copy()
    # Repo slug, so 'tempo-io/nexus' and 'nexus' (CodeQL rows have no org) are one repo.
    repo_slug = out["repository"].map(_repo_slug).fillna("")
    base = repo_slug + "|" + out["identifier"].fillna("").astype(str)
    category = out["violation_category"]
    secret = category.eq("SecretDetection")
    sca = category.eq("SCA")
    other = ~(secret | sca)
    location = out["file_path"].fillna("").astype(str) + "|" + out["line"].astype(str)
    key = base.copy()
    key[sca] = base[sca] + "|" + out.loc[sca, "package_name"].fillna("").astype(str)
    key[other] = base[other] + "|" + location[other]
    out["issue_key"] = key
    return out

def _pct(numerator: float, denominator: float) -> float:
    return round(100 * numerator / denominator, 1) if denominator else float("nan")

def _extra_group_metrics(subset: pd.DataFrame) -> dict:
    reduced_subset = reduce_noise_repetitive_violations(subset)
    actionable_rows = subset[subset["triage_tier"] == "Actionable"]
    actionable_issues = reduced_subset[reduced_subset["triage_tier"] == "Actionable"]
    secrets = subset[subset["violation_category"] == "SecretDetection"]
    act_secrets = actionable_issues[actionable_issues["violation_category"] == "SecretDetection"]
    act_sca = actionable_issues[actionable_issues["violation_category"] == "SCA"]
    policy_counts = subset["policy"].value_counts()
    live_secrets = act_secrets[act_secrets["tag_latest_code"] & ~act_secrets["tag_test_file"]]
    return {
        # X1
        "actionable_rows": int(len(actionable_rows)),
        "actionable_unique_issues": int(actionable_issues["issue_key"].nunique()),
        "rows_per_issue": round(len(actionable_rows) / max(actionable_issues["issue_key"].nunique(), 1), 1),
        # X2
        "actionable_sca": int(len(act_sca)),
        "actionable_sca_fix_available_pct": _pct(act_sca["fix_available"].fillna(False).astype(bool).sum(), len(act_sca)),
        # X3
        "actionable_secrets": int(len(act_secrets)),
        "actionable_secrets_live": int(len(live_secrets)),
        # X4
        "test_file_share_pct": _pct(subset["tag_test_file"].sum(), len(subset)),
        "secrets_ai_verified_pct": _pct(secrets["tag_ai_verified"].sum(), len(secrets)),
        # X5
        "owner_named_pct_all": _pct(subset["user"].notna().sum(), len(subset)),
        "owner_named_pct_actionable": _pct(actionable_issues["user"].notna().sum(), len(actionable_issues)),
        # X6
        "top5_policy_share_pct": _pct(policy_counts.head(5).sum(), len(subset)),
        "top_policy": policy_counts.index[0] if len(policy_counts) else None,
    }

def summarize_extra_metrics(violations_df: pd.DataFrame, group_column: str = "Project") -> pd.DataFrame:
    """
    X1-X6 per group (Project or Team). Adds issue_key itself if missing.
    A TOTAL row is appended so the table can be checked against the whole file.
    """
    frame = violations_df if "issue_key" in violations_df.columns else add_issue_key(violations_df)
    groups = sorted(frame[group_column].dropna().unique())
    table = pd.DataFrame({g: _extra_group_metrics(frame[frame[group_column] == g]) for g in groups}).T
    table.loc["TOTAL"] = _extra_group_metrics(frame)
    table.index.name = group_column
    return table

def actionable_mix_by_category(violations_df: pd.DataFrame, group_column: str = "Project") -> pd.DataFrame:
    """X7. Count of Actionable findings by violation category, per group."""
    actionable = violations_df[violations_df["triage_tier"] == "Actionable"]
    return pd.crosstab(actionable[group_column], actionable["violation_category"], margins=True, margins_name="TOTAL")

def summarize_triage_activity(audits_df: pd.DataFrame) -> pd.DataFrame:
    """
    X8. Weekly triage activity from the audit log (org level; events have no repo).

    detection_changes  : Detection "Modified" events (triage actions)
    automation_share   : share made by "Service Account"
    human_changes      : the rest
    config_changes     : everything that is not a Detection event (labels,
                         integrations, projects, classification rules, risk formula)
    Weeks with no events are included as zeros so gaps in activity are visible.
    """
    events = audits_df.copy()
    events["week"] = (
        pd.to_datetime(events["event_time"], errors="coerce", utc=True, format="mixed")
        .dt.tz_localize(None).dt.to_period("W").dt.start_time
    )
    is_triage = events["resource_type"].eq("Detection") & events["action"].eq("Modified")
    is_auto = events["user"].eq("Service Account")
    weekly = pd.DataFrame({
        "detection_changes": events[is_triage].groupby("week").size(),
        "automated": events[is_triage & is_auto].groupby("week").size(),
        "config_changes": events[~events["resource_type"].eq("Detection")].groupby("week").size(),
    })
    full_range = pd.date_range(weekly.index.min(), weekly.index.max(), freq="7D")
    weekly = weekly.reindex(full_range).fillna(0).astype(int)
    weekly["human_changes"] = weekly["detection_changes"] - weekly["automated"]
    weekly["automation_share_pct"] = [_pct(a, d) for a, d in zip(weekly["automated"], weekly["detection_changes"])]
    weekly.index.name = "week_start"
    return weekly

def reduce_noise_repetitive_violations(violations_df: pd.DataFrame) -> pd.DataFrame:
    """
    Collapse repeated rows of the same underlying issue into one row.

    "Same issue" is `issue_key` (see add_issue_key): secrets by repo + secret
    hash, SCA by repo + CVE + package, everything else by repo + policy + file
    + line. Distinct secrets, packages or locations are never merged, which a
    key built only from policy/repo/severity would do. Open and Resolved rows
    never merge (status_raw is part of the key).

    The kept row is the most important occurrence: best triage tier first
    (an issue is Noise only if EVERY occurrence is Noise), then highest risk
    score. Adds `occurrences` = number of raw rows merged into it.
    Expects add_triage_and_age() to have run. Input is not modified.
    """
    required = {"triage_tier", "risk_score"}
    missing = required - set(violations_df.columns)
    if missing:
        raise KeyError(f"run add_triage_and_age first; missing columns: {sorted(missing)}")
    frame = violations_df if "issue_key" in violations_df.columns else add_issue_key(violations_df)
    status = frame["status_raw"] if "status_raw" in frame.columns else frame["status"].astype(str)
    group_key = frame["issue_key"].astype(str) + "|" + status.astype(str)

    ranked = frame.assign(
        _group=group_key,
        _tier_rank=frame["triage_tier"].map({t: i for i, t in enumerate(TIER_ORDER)}).fillna(len(TIER_ORDER)),
        _score=pd.to_numeric(frame["risk_score"], errors="coerce").fillna(-1),
    ).sort_values(["_tier_rank", "_score"], ascending=[True, False], kind="mergesort")
    occurrences = ranked.groupby("_group")["_group"].transform("size")
    reduced = ranked.assign(occurrences=occurrences).drop_duplicates("_group")
    return reduced.drop(columns=["_group", "_tier_rank", "_score"]).reset_index(drop=True)

def summarize_noise_after_dedup(violations_df: pd.DataFrame, dimension: str = "Project") -> pd.DataFrame:
    """
    X9. Noise before and after removing repeated rows, per group.

    rows            : raw open findings (what Cycode counts)
    issues          : distinct issues after reduce_noise_repetitive_violations
    repeat_factor   : rows per issue (1.0 = no repetition)
    noise_rate_rows : % of rows in the Noise tier
    noise_rate_issues: % of issues that are Noise (every occurrence Noise)
    actionable_rows / actionable_issues : the real work, before and after
    duplicate_share_pct: % of rows that were repeats of another row

    Only open findings are used. A TOTAL row is appended. Never add the
    dimensions together.
    """
    status = violations_df["status_raw"] if "status_raw" in violations_df.columns else violations_df["status"]
    open_df = violations_df[status.astype(str).str.lower().eq("open")]
    if open_df.empty:
        return pd.DataFrame()
    reduced = reduce_noise_repetitive_violations(open_df)
    open_df = open_df.assign(_g=_dimension_series(open_df, dimension))
    reduced = reduced.assign(_g=_dimension_series(reduced, dimension))

    def row(rows: pd.DataFrame, issues: pd.DataFrame) -> dict:
        r, i = len(rows), len(issues)
        return {
            "rows": r,
            "issues": i,
            "repeat_factor": round(r / i, 1) if i else float("nan"),
            "duplicate_share_pct": _pct(r - i, r),
            "noise_rate_rows": _pct((rows["triage_tier"] == "Noise").sum(), r),
            "noise_rate_issues": _pct((issues["triage_tier"] == "Noise").sum(), i),
            "actionable_rows": int((rows["triage_tier"] == "Actionable").sum()),
            "actionable_issues": int((issues["triage_tier"] == "Actionable").sum()),
        }

    groups = sorted(open_df["_g"].dropna().unique(), key=str)
    table = pd.DataFrame({g: row(open_df[open_df["_g"] == g], reduced[reduced["_g"] == g]) for g in groups}).T
    table.loc["TOTAL"] = row(open_df, reduced)
    for col in ("rows", "issues", "actionable_rows", "actionable_issues"):
        table[col] = table[col].astype(int)
    table.index.name = dimension
    return table.sort_values("rows", ascending=False)

# ---------------------------------------------------------------------------
# Tuning layer: keep engineers on what matters (reporting only; Cycode is unchanged)
# ---------------------------------------------------------------------------
# Tuning decides what we SHOW as work, not what Cycode detects. It never edits
# triage_tier (the strict definition stays the headline); it adds tuned_tier and
# tuning_reason so every decision is visible and reversible. To remove noise at the
# source, apply the exclusions from noise_exclusion_candidates() inside Cycode.
# Non-capturing groups only: str.contains warns if the pattern has match groups.
NON_PROD_PATH_RE = re.compile(
    r"(?:^|/)(?:docs?|dev-cli|scripts?|examples?|samples?|fixtures?|mocks?|__mocks__|__tests__|tests?|e2e|"
    r"test-utils|storybook|\.storybook)(?:/|$)|\.(?:spec|test|stories)\.[a-z]+",
    re.IGNORECASE,
)
LOW_CONTEXT_MAX_SCORE = NOISE_MAX_SCORE       # Cycode risk score under this = low context
TUNED_ORDER = ["Actionable", "Review", "Deprioritised", "Noise"]


def apply_tuning(issues_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add tuned_tier and tuning_reason to a frame that has been through
    add_triage_and_age (ideally one row per issue, see reduce_noise_repetitive_violations).

    Rules, in order (the first that applies wins):
      1. Actionable stays Actionable. Strict Noise stays Noise.
      2. Non-production code (docs/, dev-cli/, scripts/, tests, *.spec.*, or Cycode's
         "Test file" tag) -> Deprioritised, unless Cycode itself rates it High/Critical.
      3. Low context risk (Cycode risk level Low/Info AND score < 30) -> Deprioritised,
         even when the scanner severity is higher, because Cycode's risk already
         accounts for context (reachability, running containers, test files).
         Guardrail: scanner severity Critical is NOT deprioritised by this rule.
      4. Everything else -> Review (needs a human decision).
    So Actionable is identical before and after tuning: tuning only shrinks Review.
    """
    required = {"triage_tier", "risk_level", "risk_score", "severity"}
    missing = required - set(issues_df.columns)
    if missing:
        raise KeyError(f"run add_triage_and_age first; missing columns: {sorted(missing)}")
    out = issues_df.copy()
    tier = out["triage_tier"].astype(str)
    level = out["risk_level"].astype(str).str.lower()
    score = pd.to_numeric(out["risk_score"], errors="coerce")
    severity = out["severity"].map(lambda v: str(getattr(v, "value", v)).lower())
    path = out["file_path"].fillna("").astype(str) if "file_path" in out else pd.Series("", index=out.index)
    test_tag = out["tag_test_file"].fillna(False).astype(bool) if "tag_test_file" in out else pd.Series(False, index=out.index)

    non_prod = path.str.contains(NON_PROD_PATH_RE) | test_tag
    cycode_high = level.isin(["high", "critical"])
    low_context = level.isin(["low", "info"]) & score.lt(LOW_CONTEXT_MAX_SCORE) & severity.ne("critical")

    tuned = tier.copy()
    reason = pd.Series("", index=out.index)
    undecided = tier.eq("Review")
    rule_nonprod = undecided & non_prod & ~cycode_high
    rule_lowctx = undecided & ~rule_nonprod & low_context
    tuned[rule_nonprod | rule_lowctx] = "Deprioritised"
    reason[rule_nonprod] = "non-production path or test file"
    reason[rule_lowctx] = "low context risk (Cycode risk Low/Info, score < 30)"
    reason[tier.eq("Noise")] = "strict noise (Low/Info risk, score < 30, Low/Info severity)"
    out["tuned_tier"] = tuned
    out["tuning_reason"] = reason
    return out


def summarize_tuning(violations_df: pd.DataFrame, dimension: str = "Project") -> pd.DataFrame:
    """
    X10. Per group, open ISSUES by tier before and after tuning.

    strict_noise_pct        share of issues that are strict Noise (the headline definition)
    deprioritised           Review issues the tuning rules move out of the work queue
    review_before / after   issues needing a human decision before / after tuning
    actionable              identical before and after (tuning never touches it)
    focus_pct               actionable as a % of what is left to look at (actionable + review after)
    Only open findings. A TOTAL row is appended.
    """
    status = violations_df["status_raw"] if "status_raw" in violations_df.columns else violations_df["status"]
    open_df = violations_df[status.astype(str).str.lower().eq("open")]
    if open_df.empty:
        return pd.DataFrame()
    issues = apply_tuning(reduce_noise_repetitive_violations(open_df))
    issues = issues.assign(_g=_dimension_series(issues, dimension))

    def row(frame: pd.DataFrame) -> dict:
        n = len(frame)
        c = frame["tuned_tier"].value_counts()
        review_before = int((frame["triage_tier"] == "Review").sum())
        review_after = int(c.get("Review", 0))
        actionable = int(c.get("Actionable", 0))
        looked_at = actionable + review_after
        return {
            "issues": n,
            "strict_noise_pct": _pct(c.get("Noise", 0), n),
            "actionable": actionable,
            "review_before": review_before,
            "deprioritised": int(c.get("Deprioritised", 0)),
            "review_after": review_after,
            "focus_pct": _pct(actionable, looked_at),
        }

    groups = sorted(issues["_g"].dropna().unique(), key=str)
    table = pd.DataFrame({g: row(issues[issues["_g"] == g]) for g in groups}).T
    table.loc["TOTAL"] = row(issues)
    for col in ("issues", "actionable", "review_before", "deprioritised", "review_after"):
        table[col] = table[col].astype(int)
    table.index.name = dimension
    return table.sort_values("issues", ascending=False)


def noise_exclusion_candidates(violations_df: pd.DataFrame, top: int = 25) -> pd.DataFrame:
    """
    X11. Where to tune IN CYCODE to remove noise at the source.

    Groups the open issues that are strict Noise or Deprioritised by
    (project, category, policy, folder) and ranks them by size. `folder` is the first
    three path segments inside the repo (or "(no path)"). Apply a path exclusion or a
    severity change in Cycode for the biggest rows, then re-export: the strict noise
    rate falls only when Cycode stops reporting them.
    """
    status = violations_df["status_raw"] if "status_raw" in violations_df.columns else violations_df["status"]
    open_df = violations_df[status.astype(str).str.lower().eq("open")]
    if open_df.empty:
        return pd.DataFrame()
    issues = apply_tuning(reduce_noise_repetitive_violations(open_df))
    issues = issues[issues["tuned_tier"].isin(["Noise", "Deprioritised"])].copy()

    def folder(value: object) -> str:
        parts = [p for p in str(value or "").split("/") if p]
        if len(parts) > 2 and parts[0] == "tempo-io":
            parts = parts[2:]  # drop org and repo
        parts = parts[:-1] if len(parts) > 1 else parts  # drop the file name
        return "/".join(parts[:3]) if parts else "(no path)"

    issues["folder"] = issues["file_path"].map(folder) if "file_path" in issues else "(no path)"
    issues["repository"] = issues["repository"].map(_repo_slug)
    table = (
        issues.groupby(["Project", "repository", "violation_category", "policy", "folder", "tuned_tier"], dropna=False)
        .size().rename("issues").reset_index().sort_values("issues", ascending=False).head(top)
    )
    return table.reset_index(drop=True)

########################################################
# Insights Generation
########################################################
# Weekly insights compare this week's scorecard with the previous report's scorecard
# (the same tables the dashboard shows), so nothing is recomputed from the raw exports.
# Three kinds of finding, each a dict in the list identify_anomalies() returns:
#   change   a group's metric moved more than its threshold since the previous report
#   outlier  a group is far from its peers this week (Tukey fences across the groups)
#   data     something that makes the numbers untrustworthy (export size, Unmapped, blank cells)

# column -> (good_up, kind, min_abs, min_pct)
#   good_up  True: higher is better, False: lower is better, None: a move is reported, not judged
#   count    needs a move of at least min_abs AND min_pct percent
#   points   needs a move of at least min_abs points (rates and 0-100 scores)
# PLACEHOLDERS: tune after a few weeks of history.
ANOMALY_RULES = {
    "Open findings": (None, "count", 100, 25),
    "Open issues (distinct)": (False, "count", 50, 25),
    "M1 Actionable High/Crit open": (False, "count", 10, 20),
    "M3 MTTR Critical (median days)": (False, "count", 7, 50),
    "M3 MTTR High (median days)": (False, "count", 7, 50),
    "M4 Noise rate (%)": (False, "points", 3, 0),
    "M5 SLA breaches": (False, "count", 10, 25),
    "M5 Hygiene score (0-100)": (True, "points", 10, 0),
    "M7 Scanner coverage (%)": (True, "points", 5, 0),
    "M9 Posture score (0-100)": (True, "points", 10, 0),
}
ANOMALY_SUMMABLE = ("Open findings", "Open issues (distinct)", "M1 Actionable High/Crit open", "M5 SLA breaches")
ANOMALY_PEER_METRICS = ("M4 Noise rate (%)", "M5 Hygiene score (0-100)", "M9 Posture score (0-100)")
ANOMALY_MIN_OPEN = 20            # groups smaller than this (both weeks) are too noisy to judge
ANOMALY_UNMAPPED_SHARE = 0.20    # warn when this share of open findings is Unmapped
ANOMALY_HISTORY_CHANGES = 6      # weekly changes needed before IQR fences replace the fixed thresholds
_SEVERITY_RANK = {"high": 0, "medium": 1, "info": 2}
_KIND_RANK = {"data": 0, "change": 1, "outlier": 2}

def _scorecard(table: pd.DataFrame | None) -> pd.DataFrame:
    """A scorecard indexed by group. Accepts the frame as parsed from the report CSV (group in the first column)."""
    if table is None or len(table) == 0:
        return pd.DataFrame()
    out = table.copy()
    if isinstance(out.index, pd.RangeIndex):
        out = out.set_index(out.columns[0])
    out.index = out.index.astype(str)
    return out.apply(pd.to_numeric, errors="coerce")

def _pretty_metric(metric: str) -> str:
    match = re.match(r"^(M\d)\s+(.*)$", metric)
    return f"{match.group(2)} ({match.group(1)})" if match else metric

def _fmt_metric(metric: str, value: float) -> str:
    if pd.isna(value):
        return "blank"
    if "(%)" in metric:
        return f"{value:.1f}%"
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.1f}"

def _history_fences(history: pd.DataFrame | None, dimension: str, snapshot_date: str | None) -> dict:
    """
    {(group, metric): (low, high)} Tukey fences of the weekly CHANGES before this week.
    Needs ANOMALY_HISTORY_CHANGES earlier changes; otherwise the fixed thresholds are used.
    """
    if history is None or len(history) == 0 or snapshot_date is None:
        return {}
    h = history[(history["dimension"] == dimension) & history["metric"].isin(ANOMALY_RULES)]
    h = h[h["snapshot_date"].astype(str) < snapshot_date]
    fences = {}
    for (group, metric), part in h.groupby(["group", "metric"]):
        series = part.sort_values("snapshot_date")["value"].astype(float).dropna()
        changes = series.diff().dropna()
        if len(changes) < ANOMALY_HISTORY_CHANGES:
            continue
        q1, q3 = changes.quantile(0.25), changes.quantile(0.75)
        spread = q3 - q1
        if spread > 0:
            fences[(str(group), metric)] = (q1 - 1.5 * spread, q3 + 1.5 * spread)
    return fences

def _judge_change(metric: str, before: float, after: float, fence: tuple | None) -> dict | None:
    """The size and direction of one move, or None when it is below the threshold."""
    good_up, kind, min_abs, min_pct = ANOMALY_RULES[metric]
    change = after - before
    pct = (abs(change) / abs(before) * 100) if before else (float("inf") if change else 0.0)
    material = abs(change) >= min_abs and (kind == "points" or pct >= min_pct)
    if material and fence is not None:
        material = change < fence[0] or change > fence[1]
    if not material:
        return None
    if good_up is None:
        direction = "changed"
    else:
        direction = "better" if (change > 0) == good_up else "worse"
    big = abs(change) >= 2 * min_abs and (kind == "points" or pct >= 2 * min_pct)
    severity = ("high" if big else "medium") if direction == "worse" else "info"
    return {"change": change, "pct": pct, "direction": direction, "severity": severity,
            "magnitude": abs(change) / min_abs}

def _change_message(group: str, metric: str, before: float, after: float, judged: dict, dimension: str) -> str:
    verb = "rose" if judged["change"] > 0 else "fell"
    label = {"worse": "Worse", "better": "Better", "changed": "Changed"}[judged["direction"]]
    size = (f"{judged['change']:+,.1f} points" if ANOMALY_RULES[metric][1] == "points"
            else (f"{judged['pct']:+.0f}%" if judged["pct"] != float("inf") else "from zero"))
    if judged["change"] < 0 and ANOMALY_RULES[metric][1] != "points" and judged["pct"] != float("inf"):
        size = f"-{judged['pct']:.0f}%"
    return (f"{label}: {group} {_pretty_metric(metric)} {verb} from {_fmt_metric(metric, before)} "
            f"to {_fmt_metric(metric, after)} ({size}).")

def identify_anomalies(
    current: pd.DataFrame,
    previous: pd.DataFrame | None,
    dimension: str = "Project",
    history: pd.DataFrame | None = None,
    snapshot_date: str | None = None,
) -> list[dict]:
    """
    Compare this week's scorecard with the previous report's and list what needs attention.

    current / previous  "Scorecard <dimension>" tables, one row per group (as written in
                        cycode_metrics_<date>.csv, or indexed by group).
    history             optional state/metrics_history.csv. A group-metric with at least
                        ANOMALY_HISTORY_CHANGES earlier weekly changes is judged against its
                        own IQR fences instead of the fixed thresholds in ANOMALY_RULES.
    snapshot_date       "YYYY-MM-DD" of the current report (needed with history).

    Returns dicts with kind (change / outlier / data), severity (high / medium / info),
    dimension, group, metric, previous, current, change, message, plus anomaly_name and
    anomaly_message. Sorted: high first, data checks before moves before peer outliers,
    biggest first. Groups with fewer than ANOMALY_MIN_OPEN open findings in both weeks are
    skipped. Hygiene, noise rate and similar rates are never summed into an org figure.
    """
    cur, prev = _scorecard(current), _scorecard(previous)
    out: list[dict] = []

    def add(kind, severity, group, metric, before, after, message, magnitude=0.0):
        out.append({"kind": kind, "severity": severity, "dimension": dimension, "group": group, "metric": metric,
                    "previous": before, "current": after,
                    "change": (after - before) if pd.notna(before) and pd.notna(after) else float("nan"),
                    "message": message, "magnitude": magnitude,
                    "anomaly_name": f"{'Low' if (after or 0) < (before or 0) else 'High'} {metric}" if metric else message[:40],
                    "anomaly_message": message})

    if cur.empty:
        return out
    if prev.empty:
        add("data", "info", "All", "", float("nan"), float("nan"),
            "No previous report to compare with, so week-over-week changes cannot be checked yet.")
    fences = _history_fences(history, dimension, snapshot_date)
    open_now = cur["Open findings"] if "Open findings" in cur else pd.Series(0.0, index=cur.index)
    open_before = prev["Open findings"].reindex(cur.index) if (not prev.empty and "Open findings" in prev) else pd.Series(dtype=float)

    # --- moves per group -----------------------------------------------------------------
    blanked = []
    if not prev.empty:
        for group in cur.index:
            if group not in prev.index:
                # "Unmapped" appearing is reported by the Unmapped data check below, not as a new group.
                if open_now.get(group, 0) >= ANOMALY_MIN_OPEN and group.lower() != "unmapped":
                    add("data", "info", group, "Open findings", float("nan"), float(open_now[group]),
                        f"New: {group} appears this week with {open_now[group]:,.0f} open findings "
                        f"(check the {dimension.lower()} map if it should already exist).")
                continue
            if max(open_now.get(group, 0) or 0, open_before.get(group, 0) or 0) < ANOMALY_MIN_OPEN:
                continue
            for metric in ANOMALY_RULES:
                if metric not in cur.columns or metric not in prev.columns:
                    continue
                before, after = prev.at[group, metric], cur.at[group, metric]
                if pd.isna(before):
                    continue
                if pd.isna(after):
                    blanked.append(metric)
                    continue
                judged = _judge_change(metric, before, after, fences.get((group, metric)))
                if judged:
                    add("change", judged["severity"], group, metric, before, after,
                        _change_message(group, metric, before, after, judged, dimension), judged["magnitude"])
                    out[-1]["direction"] = judged["direction"]
        for group in prev.index.difference(cur.index):
            if (prev["Open findings"].get(group, 0) or 0) >= ANOMALY_MIN_OPEN if "Open findings" in prev else False:
                add("data", "info", group, "Open findings", float(prev["Open findings"][group]), float("nan"),
                    f"Gone: {group} had {prev['Open findings'][group]:,.0f} open findings last week and is missing now.")
        # org totals for the metrics that can be added up within one grouping
        for metric in ANOMALY_SUMMABLE:
            if metric in cur.columns and metric in prev.columns:
                before, after = prev[metric].sum(), cur[metric].sum()
                judged = _judge_change(metric, before, after, None)
                if judged:
                    add("change", judged["severity"], f"All {dimension.lower()}s", metric, before, after,
                        _change_message(f"All {dimension.lower()}s", metric, before, after, judged, dimension),
                        judged["magnitude"] * 1.5)
                    out[-1]["direction"] = judged["direction"]

    # --- data checks ---------------------------------------------------------------------
    baseline_changed = False
    if not prev.empty and "Open findings" in cur and "Open findings" in prev:
        now, before = cur["Open findings"].sum(), prev["Open findings"].sum()
        if before and abs(now - before) / before > ROW_COUNT_TOLERANCE:
            baseline_changed = True
            add("data", "high", "All", "Open findings", before, now,
                f"Check data: the export size changed from {before:,.0f} to {now:,.0f} rows "
                f"({(now - before) / before:+.0%}). If the export filters changed, treat this week as a new baseline.",
                abs(now - before) / before * 10)
    unmapped = [g for g in cur.index if g.lower() == "unmapped"]
    if unmapped and open_now.sum():
        share = float(open_now[unmapped[0]]) / float(open_now.sum())
        if share >= ANOMALY_UNMAPPED_SHARE:
            add("data", "medium", unmapped[0], "Open findings", float("nan"), float(open_now[unmapped[0]]),
                f"Check data: {open_now[unmapped[0]]:,.0f} open findings ({share:.0%}) are Unmapped. "
                "Add those repositories to product_map.csv; until then every score excludes them and looks better than it is.",
                share * 10)
    if len(blanked) >= 3:
        names = ", ".join(sorted({_pretty_metric(m) for m in blanked})[:3])
        add("data", "medium", "All", "", float("nan"), float("nan"),
            f"Check data: {len(blanked)} score cells that had values last week are blank now (for example {names}). "
            "That usually means an export or audit-log gap, not a real improvement.", len(blanked) / 10)

    # --- peers: who is far from the others this week -----------------------------------------
    for metric in ANOMALY_PEER_METRICS:
        if metric not in cur.columns:
            continue
        sized = cur[(open_now.fillna(0) >= ANOMALY_MIN_OPEN) & ~cur.index.str.lower().isin(["unmapped"])]
        values = sized[metric].dropna()
        if len(values) < 5:
            continue
        q1, q3 = values.quantile(0.25), values.quantile(0.75)
        spread = q3 - q1
        if spread <= 0:
            continue
        good_up = ANOMALY_RULES[metric][0]
        bad = values[values < q1 - 1.5 * spread] if good_up else values[values > q3 + 1.5 * spread]
        for group, value in bad.items():
            add("outlier", "medium", group, metric, float("nan"), float(value),
                f"Unusual: {group} is far from the other {dimension.lower()}s on {_pretty_metric(metric)}: "
                f"{_fmt_metric(metric, value)} against a typical {_fmt_metric(metric, values.median())}.",
                abs(value - values.median()) / spread)

    # A different export size moves every group at once. Those moves are probably the new baseline, not
    # real movement, so they are flagged and capped at medium (attain_insights summarises them).
    for item in out:
        item["baseline_shift"] = bool(baseline_changed and item["kind"] == "change")
        if item["baseline_shift"] and item["severity"] == "high":
            item["severity"] = "medium"
    out.sort(key=lambda a: (_SEVERITY_RANK[a["severity"]], _KIND_RANK[a["kind"]], -float(a["magnitude"] or 0)))
    return out

def attain_insights(anomalies: list[dict], limit: int = 10) -> list[str]:
    """
    The messages to show, most important first: high severity, then data checks, moves and peer
    outliers. Capped at `limit`; the last line says how many were left out. When nothing moved
    beyond the thresholds the single line says so (an empty week is information too).
    """
    if not anomalies:
        return ["Nothing moved beyond the thresholds since the previous report."]
    shifted = [a for a in anomalies if a.get("baseline_shift")]
    if shifted:
        # Keep the data warnings, then only the largest moves, with one line explaining why.
        keep = [a for a in anomalies if not a.get("baseline_shift")]
        top = sorted(shifted, key=lambda a: -float(a["magnitude"] or 0))[:4]
        messages = [a["message"] for a in keep if a["kind"] == "data"]
        messages.append(f"{len(shifted)} group-level moves follow from the export size change and are probably the new "
                        "baseline rather than real movement. The largest, for reference:")
        messages += [a["message"] for a in top]
        messages += [a["message"] for a in keep if a["kind"] != "data"]
    else:
        messages = [a["message"] for a in anomalies]
    if len(messages) > limit:
        messages = messages[:limit] + [f"...and {len(messages) - limit} more (see the scorecard)."]
    return messages

########################################################
# Next-step recommendations (the "What should we do next?" button)
########################################################
# The model sees only AGGREGATES: the insight messages, their numbers, group names (product or team
# names) and the dates of the two reports. No finding text, repository file paths, people or secrets.
# A rule-based playbook always works (no key, no network); the model adapts it to this week's facts.

NEXT_STEP_CAVEATS = [
    "SLA days (M5) and posture weights (M9) are placeholders; do not escalate on them alone.",
    "Scores exclude Unmapped repositories; an Unmapped share makes every score look better than it is.",
    "M3 (time to remediate) only counts findings linked to the audit log; blank or odd MTTR is usually an export or audit-log gap.",
    "Open findings are Cycode rows; distinct issues are fewer. Compare rows with issues only knowingly.",
    "The AI cost split (M8) is a 140,000/year placeholder.",
]
DASHBOARD_TABS = "Scorecard, Backlog (M1), Remediation (M3), Noise (M4), Age (M5), AI & cost (M6, M8), Coverage (M7), Posture (M9), Extras (X), Caveats"

def playbook_next_steps(anomalies: list[dict]) -> list[str]:
    """
    Standard actions for what the insights found, most urgent first, one line per kind of finding
    (groups are listed together). Deterministic; also given to the model as its starting point.
    """
    if not anomalies:
        return ["No action needed this week. Keep exporting with the same filters so next week's comparison is valid."]
    steps: list[str] = []
    seen: set = set()

    # Moves that follow from a changed export size are not a basis for action (see identify_anomalies).
    reliable = [a for a in anomalies if not a.get("baseline_shift")]
    held = len(anomalies) - len(reliable)

    def groups_of(predicate) -> str:
        names = []
        for a in reliable:
            if predicate(a) and a["group"] not in names:
                names.append(a["group"])
        return ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")

    def add(key: str, text: str) -> None:
        if key not in seen:
            seen.add(key)
            steps.append(text)

    data = [a for a in anomalies if a["kind"] == "data"]
    if any(a.get("baseline_shift") for a in anomalies) or any("export size" in a["message"] for a in data):
        add("size", "Verify first: confirm the open and closed exports use the same filters as last week (same statuses, same date range). "
                    "If they changed, treat this week as a new baseline and ignore group-level week-over-week moves until next week.")
    if any("Unmapped" in a["message"] and "open findings (" in a["message"] for a in data):
        add("unmapped", "Verify first: assign the Unmapped repositories to a product line and team in product_map.csv (see the "
                        "TO CONFIRM rows), then re-run the report so the group scores include them.")
    if any("blank now" in a["message"] for a in data):
        add("blank", "Verify first: re-fetch the audit log through today and check that 'Last Status Change' is filled in the closed export; "
                     "blank MTTR cells are an export gap, not an improvement.")
    if held:
        add("held", f"Hold group-level actions: {held} week-over-week moves are probably the new export baseline. Re-check them "
                    "next week against an export with unchanged filters.")
    if any("No previous report" in a["message"] for a in data):
        add("first", "Keep this report; next week's export enables the week-over-week comparison.")
    if any("appears this week" in a["message"] for a in data):
        add("new", "Check that new groups are expected (a new product or a renamed team) and that product_map.csv covers them.")

    def moved(metric_prefix: str, direction: str = "worse"):
        return lambda a: a["kind"] == "change" and a["metric"].startswith(metric_prefix) and a.get("direction") == direction

    for prefix, key, text in (
        ("M1 ", "m1", "Backlog of actionable findings grew in {g}: open the Backlog (M1) tab and the actionable list for those groups, "
                      "assign owners, and start with known-exploited and Critical items."),
        ("M5 SLA", "sla", "SLA breaches rose in {g}: review the oldest actionable findings in the Age (M5) tab. SLA days are placeholders, "
                          "so confirm the targets with security and engineering before escalating."),
        ("M5 Hygiene", "hyg", "Hygiene fell in {g}: see Age (M5) for which severity breached; check whether one scan burst or one repository drives it."),
        ("M4 ", "noise", "Noise rate rose in {g}: use the Noise (M4) tab and Extras (X11) to find the policies and paths to exclude or retune in Cycode."),
        ("M9 ", "posture", "Posture fell in {g}: the Posture (M9) tab lists the top policies behind the exposure; fix or retune those first."),
        ("M3 ", "mttr", "Time to remediate rose in {g}: confirm the audit-log coverage before concluding remediation slowed (Caveats tab), then check what is blocking fixes."),
        ("Open", "open", "Open findings rose in {g}: compare 'First detected' dates for a scan burst or a newly onboarded repository before treating it as new risk."),
    ):
        names = groups_of(moved(prefix))
        if names:
            add(key, text.format(g=names))
    better = groups_of(lambda a: a["kind"] == "change" and a.get("direction") == "better")
    if better:
        add("better", f"Improvements in {better}: find out what changed (a cleanup, an exclusion, a fix) so it can be repeated elsewhere.")
    outliers = groups_of(lambda a: a["kind"] == "outlier")
    if outliers:
        add("outlier", f"{outliers} sit far from their peers: open the Scorecard and Extras (X6) for their policy mix and ask the owning team what is different.")
    return steps[:8]

def _call_llm(messages: list[dict], max_tokens: int = 900) -> tuple[str, str]:
    """
    Anthropic Messages API call for the next-steps button. Returns (text, model).

    Reads ANTHROPIC_API_KEY (required) and ANTHROPIC_MODEL (optional; default claude-sonnet-5-5). If the
    configured model is not found, the other default is tried. `messages` keeps the chat shape used by
    recommend_next_steps: any "system" entries become the API's system prompt.
    """
    import os
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY is not set")
    # import anthropic  ## imported here so the pipeline still loads without the SDK installed

    from groq import Groq
    client = Groq(api_key=api_key, timeout=60.0, max_retries=2)
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
    models: list[str] = []
    for candidate in (os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b"), "openai/gpt-4o-mini", ""):
        if candidate and candidate not in models:
            models.append(candidate)
    last: Exception | None = None
    for model in models:
        try:
            response = client.messages.create(model=model, max_tokens=max_tokens, temperature=0.2,
                                              system=system, messages=turns)
            text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text").strip()
            if text:
                return text, getattr(response, "model", model)
        except Exception as exc:  # try the next model only when this one is missing; surface anything else
            last = exc
            if getattr(exc, "status_code", None) == 404 or "not_found" in str(exc).lower():
                continue
            raise
    raise last or RuntimeError("no model returned text")

def recommend_next_steps(anomalies: list[dict], context: dict | None = None, max_items: int = 15) -> dict:
    """
    An opinion on what to do next, for the insight popup's button.

    anomalies  the list from identify_anomalies()
    context    optional {"report", "compared_with", "grouped_by"} for the prompt
    Returns {"text": markdown, "source": model name or why the playbook was used, "playbook": [lines]}.
    The playbook is the fallback and is also given to the model as the baseline to adapt, so the answer
    stays grounded in this week's facts. The model is told not to invent numbers, CVEs or causes.
    """
    context = context or {}
    playbook = playbook_next_steps(anomalies)
    fallback_text = "**Suggested next steps**\n\n" + "\n".join(f"{i}. {line}" for i, line in enumerate(playbook, 1))
    if not anomalies:
        return {"text": fallback_text, "source": "playbook (nothing to explain)", "playbook": playbook}

    facts = []
    for a in anomalies[:max_items]:
        facts.append({k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in {
            "kind": a["kind"], "severity": a["severity"], "group": a["group"], "metric": a["metric"],
            "previous": a["previous"], "current": a["current"], "baseline_shift": a.get("baseline_shift", False),
            "message": a["message"]}.items()})
    import json
    system = (
        "You advise a security program lead who reads a weekly Cycode metrics dashboard. You are given this week's "
        "insights as structured facts. Write a short, concrete opinion on what to do next.\n"
        "Rules: use ONLY the facts and the playbook provided; never invent numbers, CVEs, causes or people; label any "
        "explanation as a hypothesis; if a data check is present (export size, Unmapped, blank cells, no previous report), "
        "list the data steps FIRST because moves are unreliable until they are resolved; do not recommend escalation based on "
        "placeholder SLA or weights alone; keep it under 250 words.\n"
        "Format exactly:\n**Read this first** (1-2 sentences)\n**Next steps** (numbered, at most 6; each: the action, why "
        "(cite the insight), where to look using only these dashboard tabs: " + DASHBOARD_TABS + ", and who would own it)\n"
        "**Check before acting** (bullets for the caveats that apply)."
    )
    user = json.dumps({
        "report": context.get("report"), "compared_with": context.get("compared_with"), "grouped_by": context.get("grouped_by"),
        "insights": facts, "playbook": playbook, "caveats": NEXT_STEP_CAVEATS,
    }, default=str, indent=1)
    try:
        text, model = _call_llm([{"role": "system", "content": system}, {"role": "user", "content": user}])
        return {"text": text, "source": model, "playbook": playbook}
    except Exception as exc:  # no key, no network, rate limit: the playbook still answers
        reason = re.sub(r"(sk-ant-|gsk_)[A-Za-z0-9_\-]+", "<key>", f"{type(exc).__name__}: {exc}")[:120]
        return {"text": fallback_text, "source": f"playbook (AI unavailable: {reason})", "playbook": playbook}

# ---------------------------------------------------------------------------
# ML layer (advisory): rank and flag, never decide
# ---------------------------------------------------------------------------
# Everything here ADDS columns (ml_*). It never edits triage_tier or tuned_tier, and it
# can never mark an Actionable issue (High/Critical Cycode risk or score >= 70) as noise.
# scikit-learn / matplotlib are imported lazily so the core pipeline runs without them.
ML_MIN_PRECISION = 0.95         # a "noise candidate" must be right this often on held-out data
ML_MIN_TRAIN_ROWS = 500
ML_MIN_CLASS_ROWS = 50
SLOW_FIX_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}   # placeholders, not policy
_ML_CATEGORICAL = ["category", "policy", "severity", "risk_level", "repo", "group", "team", "ext"]
_ML_NUMERIC = ["risk_score", "path_depth", "non_prod", "test_file", "fix_available", "has_package"]


def _sk():
    """Import scikit-learn on first use, with a clear message if it is missing."""
    try:
        import sklearn  # noqa: F401
        return sklearn
    except ImportError as exc:
        raise ImportError("scikit-learn is required for the ML layer: pip install scikit-learn") from exc


def _sev_str(series: pd.Series) -> pd.Series:
    return series.map(lambda v: str(getattr(v, "value", v)).lower())


def build_ml_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detection-time features only (what is known the day a finding appears).
    Deliberately excludes status, resolved_at, last_status_change, status_reason and
    age: they are the label or leak it. Index is preserved so rows can be joined back.
    """
    idx = df.index

    def col(name, default=""):
        return df[name] if name in df.columns else pd.Series(default, index=idx)

    path = col("file_path").fillna("").astype(str)
    feats = pd.DataFrame(index=idx)
    feats["category"] = col("violation_category").fillna("").astype(str)
    feats["policy"] = col("policy").fillna("").astype(str)
    feats["severity"] = _sev_str(col("severity", "unknown"))
    feats["risk_level"] = col("risk_level").fillna("").astype(str).str.lower()
    feats["repo"] = col("repository").fillna("").astype(str).map(_repo_slug)
    group = df["product_line"] if "product_line" in df.columns else col("project")
    feats["group"] = group.fillna("").astype(str)
    feats["team"] = col("team").fillna("").astype(str)
    feats["ext"] = path.str.extract(r"\.([A-Za-z0-9]{1,6})$", expand=False).fillna("").str.lower()
    feats["risk_score"] = pd.to_numeric(col("risk_score", np.nan), errors="coerce").fillna(-1)
    feats["path_depth"] = path.str.count("/")
    feats["non_prod"] = path.str.contains(NON_PROD_PATH_RE).astype(int)
    feats["test_file"] = col("tag_test_file", False).fillna(False).astype(bool).astype(int)
    feats["fix_available"] = col("fix_available", False).fillna(False).astype(bool).astype(int)
    feats["has_package"] = col("package_name").notna().astype(int) if "package_name" in df.columns else 0
    return feats[_ML_CATEGORICAL + _ML_NUMERIC]


def build_dismissal_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    One row per closed ISSUE: label 1 = Dismissed, 0 = Resolved.
    Needs both classes (the original code kept only dismissed rows, so nothing could
    be learned). Repeats of one issue are collapsed so the same finding can never sit
    in both train and test. Returns the features plus label, issue_key, detected_at.
    """
    status = df["status_raw"].astype(str).str.lower()
    closed = df[status.isin(["dismissed", "resolved"])]
    if closed.empty:
        return pd.DataFrame()
    closed = closed if "issue_key" in closed.columns else add_issue_key(closed)
    detected = pd.to_datetime(closed["detected_at"] if "detected_at" in closed.columns
                              else closed["first_detected_at"], errors="coerce", utc=True)
    closed = closed.assign(_label=status[closed.index].eq("dismissed").astype(int), _det=detected)
    # an issue with any Dismissed row counts as dismissed; earliest detection is its start
    agg = closed.groupby("issue_key").agg(label=("_label", "max"), detected_at=("_det", "min"))
    first = closed.drop_duplicates("issue_key").set_index("issue_key")
    feats = build_ml_features(first.reset_index(drop=True)).set_index(first.index)
    out = feats.join(agg)
    out["issue_key"] = out.index
    return out.dropna(subset=["detected_at"]).reset_index(drop=True)


def _make_dismissal_pipeline(random_state: int = 42):
    _sk()
    from sklearn.compose import ColumnTransformer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
    pre = ColumnTransformer(
        [("cat", OneHotEncoder(handle_unknown="ignore", min_frequency=20), _ML_CATEGORICAL)],
        remainder="passthrough",
    )
    forest = RandomForestClassifier(
        n_estimators=300, min_samples_leaf=5, class_weight="balanced_subsample",
        n_jobs=-1, random_state=random_state,
    )
    return Pipeline([("prep", pre), ("rf", forest)])


def train_dismissal_model(all_violations: pd.DataFrame, test_fraction: float = 0.2) -> dict:
    """
    Learn which findings tend to be Dismissed (noise) rather than Resolved (real work).

    Split is by TIME (newest issues are the test set), so the score answers "would this
    have worked on next month's findings?". The threshold is the lowest probability at
    which held-out precision >= ML_MIN_PRECISION; if none reaches it, threshold is None
    and nothing is ever flagged (a safe default for an advisory model).
    Returns {"model", "threshold", "metrics", "ok", "message"}.
    """
    _sk()
    from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
    data = build_dismissal_labels(all_violations)
    result = {"model": None, "threshold": None, "metrics": {}, "ok": False, "message": ""}
    if len(data) < ML_MIN_TRAIN_ROWS or data["label"].value_counts().min() < ML_MIN_CLASS_ROWS:
        result["message"] = "not enough closed issues in both classes to train"
        return result
    data = data.sort_values("detected_at")
    cut = int(len(data) * (1 - test_fraction))
    train, test = data.iloc[:cut], data.iloc[cut:]
    if train["label"].nunique() < 2 or test["label"].nunique() < 2:
        result["message"] = "train or test split holds only one class"
        return result
    cols = _ML_CATEGORICAL + _ML_NUMERIC
    model = _make_dismissal_pipeline()
    model.fit(train[cols], train["label"])
    prob = model.predict_proba(test[cols])[:, list(model.classes_).index(1)]
    precision, recall, thresholds = precision_recall_curve(test["label"], prob)
    ok = np.where(precision[:-1] >= ML_MIN_PRECISION)[0]
    threshold = float(thresholds[ok[0]]) if len(ok) else None
    flagged = (prob >= threshold) if threshold is not None else np.zeros(len(prob), bool)
    result.update(
        model=model, threshold=threshold, ok=threshold is not None,
        metrics={
            "train_issues": int(len(train)), "test_issues": int(len(test)),
            "base_rate_dismissed": round(float(test["label"].mean()), 3),
            "roc_auc": round(float(roc_auc_score(test["label"], prob)), 3),
            "avg_precision": round(float(average_precision_score(test["label"], prob)), 3),
            "flagged_test_issues": int(flagged.sum()),
            "precision_at_threshold": round(float(test["label"][flagged].mean()), 3) if flagged.any() else None,
            "recall_at_threshold": round(float(flagged[test["label"].to_numpy() == 1].mean()), 3),
        },
        message="ok" if threshold is not None
        else f"no threshold reaches {ML_MIN_PRECISION:.0%} precision on held-out data; nothing will be flagged",
    )
    return result


def predict_dismissed(bundle: dict, issues_df: pd.DataFrame) -> pd.DataFrame:
    """
    Score open issues (one row per issue, ideally after apply_tuning).
    Adds ml_dismissal_prob and ml_noise_candidate.

    ml_noise_candidate is True only when ALL hold: the model passed its precision bar,
    the probability is at/above threshold, the issue sits in the Review tier, and Cycode
    risk is not High/Critical and scanner severity is not Critical/High. It is a
    suggestion to deprioritise; a human or Cycode policy still makes the change.
    """
    out = issues_df.copy()
    out["ml_dismissal_prob"] = np.nan
    out["ml_noise_candidate"] = False
    if not bundle or bundle.get("model") is None or out.empty:
        return out
    model = bundle["model"]
    prob = model.predict_proba(build_ml_features(out)[_ML_CATEGORICAL + _ML_NUMERIC])[:, list(model.classes_).index(1)]
    out["ml_dismissal_prob"] = prob.round(4)
    if bundle.get("threshold") is None:
        return out
    tier = out["tuned_tier"] if "tuned_tier" in out.columns else out.get("triage_tier", pd.Series("Review", index=out.index))
    level = out["risk_level"].astype(str).str.lower() if "risk_level" in out.columns else pd.Series("", index=out.index)
    sev = _sev_str(out["severity"])
    protected = level.isin(["high", "critical"]) | sev.isin(["high", "critical"])
    out["ml_noise_candidate"] = (prob >= bundle["threshold"]) & tier.astype(str).eq("Review") & ~protected
    return out


def summarize_ml_noise(scored: pd.DataFrame, dimension: str = "Project") -> pd.DataFrame:
    """X13. Per group: Review issues the model suggests deprioritising (advisory, like X10)."""
    if scored.empty or "ml_noise_candidate" not in scored.columns:
        return pd.DataFrame()
    tier = scored["tuned_tier"] if "tuned_tier" in scored.columns else scored["triage_tier"]
    work = scored.assign(_g=_dimension_series(scored, dimension), _review=tier.eq("Review"))
    grouped = work.groupby("_g")
    table = pd.DataFrame({
        "issues": grouped.size(),
        "review": grouped["_review"].sum(),
        "ml_candidates": grouped["ml_noise_candidate"].sum(),
    }).astype(int)
    table["review_after_ml"] = table["review"] - table["ml_candidates"]
    table.loc["TOTAL"] = table.sum()
    return table


def generate_isolation_forest(data: pd.DataFrame, new_data: pd.DataFrame | None = None, contamination="auto") -> dict:
    """
    Unusual rows among NUMERIC features (NaN filled with the median).
    Use it on group-week aggregates (see scan_burst_features), not on single findings:
    a finding being rare does not make it risky. Returns model, score (lower = stranger)
    and is_outlier for new_data (or data when new_data is None).
    """
    _sk()
    from sklearn.ensemble import IsolationForest
    numeric = data.select_dtypes("number")
    medians = numeric.median()
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    model.fit(numeric.fillna(medians))
    target = (new_data if new_data is not None else data)[numeric.columns].fillna(medians)
    return {
        "model": model, "columns": list(numeric.columns),
        "score": pd.Series(model.score_samples(target), index=target.index),
        "is_outlier": pd.Series(model.predict(target) == -1, index=target.index),
    }


def scan_burst_features(df: pd.DataFrame, dimension: str = "Project") -> pd.DataFrame:
    """
    Per group and ISO week: findings detected, by category and high-risk share. Feed this
    to generate_isolation_forest to spot bursts (a new scanner rule, a mass import, a
    leaked-secret wave) instead of reading them off the weekly totals.
    """
    when = pd.to_datetime(df["detected_at"] if "detected_at" in df.columns else df["first_detected_at"],
                          errors="coerce", utc=True)
    work = df.assign(_g=_dimension_series(df, dimension), _wk=when.dt.tz_localize(None).dt.to_period("W").astype(str),
                     _hi=df["risk_level"].astype(str).str.lower().isin(["high", "critical"]))
    work = work.dropna(subset=["_g"])
    work = work[work["_wk"] != "NaT"]
    counts = work.pivot_table(index=["_g", "_wk"], columns="violation_category", values="_hi",
                              aggfunc="size", fill_value=0)
    counts["total"] = counts.sum(axis=1)
    counts["high_risk_share"] = work.groupby(["_g", "_wk"])["_hi"].mean()
    return counts.reset_index().rename(columns={"_g": "group", "_wk": "week"})


def display_isolation_forest(result: dict, data: pd.DataFrame, x: str = "total", y: str = "high_risk_share"):
    """
    Return a matplotlib Figure (st.pyplot(fig) in Streamlit; no plt.show()). A decision
    boundary needs exactly two features, so this plots two columns and colours outliers.
    """
    import matplotlib
    matplotlib.use("Agg", force=False)
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6, 4))
    flag = result["is_outlier"].reindex(data.index).fillna(False).to_numpy(bool)
    ax.scatter(data.loc[~flag, x], data.loc[~flag, y], s=14, alpha=0.5, label="normal")
    ax.scatter(data.loc[flag, x], data.loc[flag, y], s=24, color="crimson", label="unusual")
    ax.set_xlabel(x)
    ax.set_ylabel(y)
    ax.legend()
    fig.tight_layout()
    return fig


def set_up_mttr_data(all_violations: pd.DataFrame) -> pd.DataFrame:
    """
    One row per FIXED issue with mttr_days = last closing - first detection, using the
    same rules as M3 (_fixed_issues: Resolved, known closing time, reason Fixed).
    Empty frame when the export has no closing times (see the M3 note).
    """
    fixed = _fixed_issues(all_violations)
    if fixed.empty:
        return pd.DataFrame()
    out = build_ml_features(fixed)
    out["mttr_days"] = ((fixed["resolved_at"] - fixed["detected_at"]).dt.total_seconds() / 86400).clip(lower=0)
    out["issue_key"] = fixed["issue_key"]
    out["detected_at"] = fixed["detected_at"]
    return out.reset_index(drop=True)


def cluster_remediation_efforts(mttr_data: pd.DataFrame, slow_days: dict | None = None, top: int = 15) -> dict:
    """
    Where does slow remediation concentrate? Slow = mttr_days above the severity limit
    (SLOW_FIX_DAYS placeholders). Returns:
      slow         the slow rows
      hotspots     (category, policy, group) counts, slowest first: the fix-leverage view,
                   one policy or repo change that unblocks many slow fixes
      clusters     KMeans labels on log(mttr), risk score and path depth, when sklearn exists
    """
    if mttr_data is None or mttr_data.empty:
        return {"slow": pd.DataFrame(), "hotspots": pd.DataFrame(), "clusters": pd.DataFrame()}
    limits = slow_days or SLOW_FIX_DAYS
    limit = mttr_data["severity"].map(limits).fillna(max(limits.values()))
    slow = mttr_data[mttr_data["mttr_days"] > limit].copy()
    hot = (slow.groupby(["category", "policy", "group"])["mttr_days"]
           .agg(slow_fixes="size", median_days="median").reset_index()
           .sort_values(["slow_fixes", "median_days"], ascending=False).head(top))
    clusters = pd.DataFrame()
    if len(slow) >= 20:
        try:
            _sk()
            from sklearn.cluster import KMeans
            from sklearn.preprocessing import StandardScaler
            X = StandardScaler().fit_transform(
                np.column_stack([np.log1p(slow["mttr_days"]), slow["risk_score"], slow["path_depth"]]))
            slow["cluster"] = KMeans(n_clusters=min(4, len(slow) // 5), n_init=10, random_state=42).fit_predict(X)
            clusters = slow.groupby("cluster").agg(
                n=("mttr_days", "size"), median_days=("mttr_days", "median"),
                median_risk=("risk_score", "median"), top_category=("category", lambda s: s.mode().iat[0]),
            ).reset_index()
        except ImportError:
            pass
    return {"slow": slow, "hotspots": hot, "clusters": clusters}

# ---------------------------------------------------------------------------
# Issue lifecycle: daily flow (X14) and SLA-miss risk (X15, X16)
# ---------------------------------------------------------------------------
SLA_RISK_MIN_EVENTS = 30      # fixes needed in a stratum before its curve is trusted
SLA_RISK_BANDS = [(0.7, "High"), (0.4, "Medium"), (0.0, "Low")]


def issue_lifecycle(all_df: pd.DataFrame, as_of=None) -> pd.DataFrame:
    """
    One row per ISSUE (issue_key) from the open + closed exports, with:
      detected_at   earliest first detection of any occurrence
      end_at        when the issue left the queue (latest closing of its occurrences);
                    as_of for issues still open
      outcome       "open" | "fixed" | "dismissed" | "closed_other" (Resolved but not
                    Fixed, e.g. SourceRemoved)
      fixed         True only for outcome == "fixed" (the event for SLA analysis)
    An issue is open while ANY occurrence is open. Issues closed with no known closing
    time are left out (they cannot be placed on a timeline), so counts can sit below
    the issue totals; see `dropped` in the frame's .attrs.
    Needs add_resolution_columns(); Project/Team/repository columns are carried when present.
    """
    required = {"status_raw", "detected_at", "resolved_at", "resolved_at_source", "resolution_reason"}
    missing = required - set(all_df.columns)
    if missing:
        raise ValueError(f"run add_resolution_columns() first; missing {sorted(missing)}")
    df = all_df if "issue_key" in all_df.columns else add_issue_key(all_df)
    if as_of is None:
        as_of = pd.to_datetime(df["snapshot_ts"], utc=True, errors="coerce").max() if "snapshot_ts" in df else pd.Timestamp.now(tz="UTC")
    as_of = pd.Timestamp(as_of)
    as_of = as_of.tz_localize("UTC") if as_of.tzinfo is None else as_of.tz_convert("UTC")

    status = df["status_raw"].astype(str).str.lower()
    is_open = status.eq("open")
    resolved_ok = status.eq("resolved") & df["resolved_at"].notna() & df["resolved_at_source"].ne("unavailable")
    fixed_row = resolved_ok & df["resolution_reason"].eq("Fixed")
    dismissed_at = _to_utc(df["last_status_change"]).where(status.eq("dismissed")) if "last_status_change" in df else pd.Series(pd.NaT, index=df.index)
    end_row = df["resolved_at"].where(resolved_ok).fillna(dismissed_at)

    work = pd.DataFrame({
        "issue_key": df["issue_key"], "detected_at": df["detected_at"], "end_row": end_row,
        "is_open": is_open, "fixed_row": fixed_row,
        "dismissed_row": status.eq("dismissed") & dismissed_at.notna(),
    }, index=df.index)
    grouped = work.groupby("issue_key")
    life = pd.DataFrame({
        "detected_at": grouped["detected_at"].min(),
        "end_at": grouped["end_row"].max(),
        "any_open": grouped["is_open"].max(),
        "any_fixed": grouped["fixed_row"].max(),
        "any_dismissed": grouped["dismissed_row"].max(),
    })
    outcome = pd.Series("closed_other", index=life.index)
    outcome[life["any_dismissed"]] = "dismissed"
    outcome[life["any_fixed"]] = "fixed"
    outcome[life["any_open"]] = "open"
    life["outcome"] = outcome
    life.loc[life["any_open"], "end_at"] = as_of
    known = life["detected_at"].notna() & life["end_at"].notna()
    dropped = int((~known).sum())
    life = life[known].copy()
    life["fixed"] = life["outcome"].eq("fixed")
    life["duration_days"] = ((life["end_at"] - life["detected_at"]).dt.total_seconds() / 86400).clip(lower=0)
    first = df.drop_duplicates("issue_key").set_index("issue_key")
    for column in ("Project", "Team", "repository", "risk_level", "violation_category", "triage_tier"):
        if column in first.columns:
            life[column] = first[column].reindex(life.index)
    life = life.drop(columns=["any_open", "any_fixed", "any_dismissed"]).reset_index()
    life.attrs["dropped"] = dropped
    life.attrs["as_of"] = as_of
    return life


def daily_issue_flow(all_df: pd.DataFrame, dimension: str | None = None, life: pd.DataFrame | None = None) -> pd.DataFrame:
    """
    X14. Per day: issues opened (first detected that day) vs issues resolved (closed that day).

    opened, resolved (Fixed + other Resolved), dismissed, net = opened - resolved,
    cumulative_net (running sum from the first day; relative to the window start, not
    the true open backlog) and open_backlog (issues open at the end of that day, an exact
    count when every closing time is known). Dismissals are shown separately because
    they leave the queue without remediation. dimension None = whole organisation;
    otherwise one block per group. Days run from the first to the last event, zero-filled.
    """
    life = issue_lifecycle(all_df) if life is None else life
    if life.empty:
        return pd.DataFrame()
    keys = pd.Series("All", index=life.index) if dimension is None else _dimension_series(life, dimension)
    if keys is None:
        return pd.DataFrame()
    life = life.assign(_g=keys.fillna("Unknown").astype(str))
    first_day = life["detected_at"].min().floor("D")
    last_day = max(life["end_at"].max(), life["detected_at"].max()).floor("D")
    days = pd.date_range(first_day.tz_localize(None), last_day.tz_localize(None), freq="D")
    blocks = []
    for group, part in life.groupby("_g"):
        opened = part["detected_at"].dt.tz_localize(None).dt.floor("D").value_counts()
        closed = part[part["outcome"] != "open"].assign(_d=lambda f: f["end_at"].dt.tz_localize(None).dt.floor("D"))
        resolved = closed[closed["outcome"].isin(["fixed", "closed_other"])]["_d"].value_counts()
        dismissed = closed[closed["outcome"].eq("dismissed")]["_d"].value_counts()
        frame = pd.DataFrame({"date": days})
        frame["group"] = group
        frame["opened"] = frame["date"].map(opened).fillna(0).astype(int)
        frame["resolved"] = frame["date"].map(resolved).fillna(0).astype(int)
        frame["dismissed"] = frame["date"].map(dismissed).fillna(0).astype(int)
        frame["net"] = frame["opened"] - frame["resolved"]
        frame["cumulative_net"] = frame["net"].cumsum()
        frame["open_backlog"] = (frame["opened"] - frame["resolved"] - frame["dismissed"]).cumsum()
        blocks.append(frame)
    out = pd.concat(blocks, ignore_index=True)
    out["date"] = out["date"].dt.strftime("%Y-%m-%d")
    return out


def _km_curve(durations: np.ndarray, events: np.ndarray):
    """Kaplan-Meier survival curve: returns (event_times, S) for 'still not fixed'."""
    order = np.argsort(durations, kind="mergesort")
    d, e = durations[order], events[order].astype(bool)
    times = np.unique(d[e])
    surv, s = [], 1.0
    for t in times:
        at_risk = (d >= t).sum()
        s *= 1 - ((d == t) & e).sum() / at_risk
        surv.append(s)
    return times, np.array(surv)


def _km_at(curve, t: float) -> float:
    times, surv = curve
    i = np.searchsorted(times, t, side="right") - 1
    return 1.0 if i < 0 else float(surv[i])


def predict_sla_risk(all_df: pd.DataFrame, sla_days: dict | None = None, actionable_only: bool = True,
                     life: pd.DataFrame | None = None) -> pd.DataFrame:
    """
    Probability that each OPEN issue misses its SLA.

    Method (survival analysis, no model training):
      * For each stratum (risk level x scanner category, falling back to risk level, then
        to all issues) build a Kaplan-Meier curve S(t) = P(not fixed by day t).
        Fixed issues are events; open issues are censored at the snapshot and dismissed or
        non-Fixed closures are censored at their closing, so open work is not ignored.
      * For an open issue of age a with SLA s:  P(miss) = S(s) / S(a)
        i.e. the chance it is still unfixed at s given it survived to a.
        Already past its SLA = 1.0 ("Breached").
    SLA comes from SLA_DAYS by Cycode risk level (placeholders). Age counts from first
    Cycode detection, the same basis as M5. Strata with fewer than SLA_RISK_MIN_EVENTS
    fixes fall back one level; with no usable curve p_miss is blank ("insufficient data").
    Returns one row per open issue: p_miss_sla, risk_band, days_to_sla, stratum, stratum_events.
    """
    sla = {k.lower(): v for k, v in (sla_days or SLA_DAYS).items()}
    life = issue_lifecycle(all_df) if life is None else life
    if life.empty or "risk_level" not in life.columns:
        return pd.DataFrame()
    life = life.copy()
    life["risk_level"] = life["risk_level"].astype(str).str.lower()
    life["violation_category"] = life.get("violation_category", pd.Series("", index=life.index)).astype(str)
    life = life[life["risk_level"].isin(sla)]

    curves = {}

    def curve_for(mask: pd.Series):
        part = life[mask]
        if int(part["fixed"].sum()) < SLA_RISK_MIN_EVENTS:
            return None
        return _km_curve(part["duration_days"].to_numpy(float), part["fixed"].to_numpy(bool)), int(part["fixed"].sum())

    def get_curve(level: str, category: str):
        for name, mask in (
            (f"{level} / {category}", (life["risk_level"] == level) & (life["violation_category"] == category)),
            (level, life["risk_level"] == level),
            ("all issues", pd.Series(True, index=life.index)),
        ):
            if name not in curves:
                curves[name] = curve_for(mask)
            if curves[name] is not None:
                return name, curves[name]
        return None, None

    open_issues = life[life["outcome"].eq("open")]
    if actionable_only and "triage_tier" in open_issues.columns:
        open_issues = open_issues[open_issues["triage_tier"].eq("Actionable")]
    rows = []
    for rec in open_issues.itertuples(index=False):
        s_days = sla[rec.risk_level]
        age = float(rec.duration_days)
        name, found = get_curve(rec.risk_level, rec.violation_category)
        if age > s_days:
            p = 1.0
        elif found is None:
            p = np.nan
        else:
            s_age = _km_at(found[0], age)
            p = 1.0 if s_age <= 0 else min(1.0, _km_at(found[0], s_days) / s_age)
        band = "Breached" if age > s_days else (
            "Insufficient data" if np.isnan(p) else next(label for cut, label in SLA_RISK_BANDS if p >= cut))
        row = {"issue_key": rec.issue_key, "risk_level": rec.risk_level, "category": rec.violation_category,
               "age_days": round(age, 1), "sla_days": s_days, "days_to_sla": round(s_days - age, 1),
               "p_miss_sla": None if np.isnan(p) else round(float(p), 3), "risk_band": band,
               "stratum": name or "none", "stratum_events": found[1] if found else 0}
        for column in ("Project", "Team", "repository"):
            if hasattr(rec, column):
                row[column] = getattr(rec, column)
        rows.append(row)
    out = pd.DataFrame(rows)
    if not out.empty:
        out["p_miss_sla"] = pd.to_numeric(out["p_miss_sla"], errors="coerce")   # all-None would stay object
    return out


def summarize_sla_risk(scored: pd.DataFrame, dimension: str = "Project") -> pd.DataFrame:
    """
    X15. Per group, open actionable issues by SLA outlook: already breached, High/Medium
    risk of missing, and expected_misses (sum of P(miss), i.e. how many the model expects
    to end up late). A TOTAL row is appended.
    """
    if scored.empty:
        return pd.DataFrame()
    keys = _dimension_series(scored, dimension)
    if keys is None:
        return pd.DataFrame()
    work = scored.assign(_g=keys.fillna("Unknown").astype(str))
    grouped = work.groupby("_g")
    table = pd.DataFrame({
        "open_actionable": grouped.size(),
        "breached": grouped["risk_band"].apply(lambda s: int((s == "Breached").sum())),
        "high_risk_of_miss": grouped["risk_band"].apply(lambda s: int((s == "High").sum())),
        "medium_risk_of_miss": grouped["risk_band"].apply(lambda s: int((s == "Medium").sum())),
        "expected_misses": grouped["p_miss_sla"].sum().round(1),
        "no_estimate": grouped["risk_band"].apply(lambda s: int((s == "Insufficient data").sum())),
    })
    table["expected_miss_pct"] = (100 * table["expected_misses"] / table["open_actionable"]).round(1)
    total = table.sum(numeric_only=True)
    total["expected_miss_pct"] = round(100 * total["expected_misses"] / total["open_actionable"], 1) if total["open_actionable"] else np.nan
    table.loc["TOTAL"] = total
    for column in ("open_actionable", "breached", "high_risk_of_miss", "medium_risk_of_miss", "no_estimate"):
        table[column] = table[column].astype(int)
    return table.sort_values("expected_misses", ascending=False)


def sla_at_risk_list(scored: pd.DataFrame, limit: int = 50) -> pd.DataFrame:
    """X16. Issues not yet breached, ranked by P(miss) then least days left: fix these first."""
    if scored.empty:
        return pd.DataFrame()
    live = scored[~scored["risk_band"].isin(["Breached", "Insufficient data"])]
    return live.sort_values(["p_miss_sla", "days_to_sla"], ascending=[False, True]).head(limit).reset_index(drop=True)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Compute Cycode metrics M1-M9, scorecards and the weekly digest.")
    parser.add_argument("--date", default="15-Oct-2026", help="export date label, e.g. 15-Oct-2026")
    parser.add_argument("--folder", default=None, help="export folder (default: ./<date>)")
    parser.add_argument("--product-map", default="../product_map.csv")
    parser.add_argument("--inventory", default=None,
                        help="By repository export (default: ~/Documents/Cycode project/Cycode - By repository - <date>.csv)")
    parser.add_argument("--out", default="reports", help="report folder for a single run")
    parser.add_argument("--update-map", action="store_true",
                        help="merge the By-repository export for --date into the product map, then stop")
    parser.add_argument("--by-repo", default=None,
                        help="By repository export for --update-map (default: ~/Documents/Cycode Project/data/Cycode - By repository - <date>.csv)")
    parser.add_argument("--apply-suggestions", action="store_true",
                        help="with --update-map: copy suggested product/team into the new rows")
    parser.add_argument("--weekly", action="store_true",
                        help="weekly digest: also keep history in --state and compare with last week")
    parser.add_argument("--state", default="state", help="history/report folder for --weekly")
    parser.add_argument("--fetch-audits", action="store_true",
                        help="with --weekly: download the audit log through the API first (needs .env)")
    parser.add_argument("--fetch-violations", action="store_true",
                        help="with --weekly: download all violations (open and closed) through the API first")
    parser.add_argument("--fetch", action="store_true",
                        help="with --weekly: shorthand for --fetch-violations --fetch-audits")
    args = parser.parse_args()
    try:
        default_inventory = str(
            Path("~/Documents/Cycode Project/data").expanduser()
            / f"Cycode - By repository - {args.date}.csv"
        )
        if args.update_map:
            by_repo_path = Path(args.by_repo or default_inventory).expanduser()
            updated, report = update_product_mapping(
                pd.read_csv(by_repo_path), load_product_map(args.product_map) if Path(args.product_map).exists() else None,
                args.date, args.apply_suggestions)
            written = write_product_map(updated, args.product_map)
            print(f"Wrote {written} (previous file kept as {written.name}.bak)")
            print(f"New repos ({len(report['new_repos'])}):")
            new = updated[updated["repo"].isin(report["new_repos"])]
            for _, r in new.iterrows():
                print(f"  {r['repo']:30} product={r['product_line']:22} suggested={r['suggested_product_line'] or '-':24} team={r['team']}")
            print("Mapped repos absent from this export:", ", ".join(report["absent_from_export"]) or "none")
            print("Still unmapped:", ", ".join(report["still_unmapped"]) or "none")
        elif args.weekly:
            run_weekly_digest(args.date, args.folder, args.state, args.product_map,
                              args.inventory, args.fetch or args.fetch_audits,
                              args.fetch or args.fetch_violations)
        else:
            run_report(args.folder or args.date, args.date, args.product_map,
                       args.inventory or default_inventory, args.out)
    except Exception as e:
        print(f"Error: {e} {traceback.format_exc()}")
