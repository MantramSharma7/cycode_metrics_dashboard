"""
Cycode security metrics dashboard (Streamlit + Plotly).

Run from the project root:
    streamlit run dashboard/cycode_dashboard.py

Input: the combined CSV written by `python cycode_pipeline.py --date <date>`
(cycode/reports/cycode_metrics_<date>.csv). Pick a file in the sidebar or upload one.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

_REPO_DIR = Path(__file__).resolve().parents[1]
_PACKAGE_DIR = _REPO_DIR / "cycode"
for _p in (str(_REPO_DIR), str(_PACKAGE_DIR), str(Path(__file__).resolve().parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)
# Streamlit keeps modules in sys.modules across reruns; reload so new helpers
# (e.g. recommend_next_steps) are visible without restarting the server.
import importlib
import cycode_pipeline as _cycode_pipeline
importlib.reload(_cycode_pipeline)
from cycode_pipeline import attain_insights, identify_anomalies, recommend_next_steps  # noqa: E402

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
DIMENSIONS = ["Project", "Team", "Repository"]
PLACEHOLDER_NOTE = "AI cost is a 140,000/year placeholder split by findings volume."
UNMAPPED_LABEL = "Unmapped"
HIDE_UNMAPPED = False  # set by the sidebar checkbox below

# For each scorecard column: True = higher is better, False = lower is better.
HIGHER_IS_BETTER = {
    "M1 Actionable High/Crit open": False,
    "M3 MTTR Critical (median days)": False,
    "M3 MTTR High (median days)": False,
    "M4 Noise rate (%)": False,
    "M5 Median detection age (days)": False,
    "M5 SLA breaches": False,
    "M5 Hygiene score (0-100)": True,
    "M6 AI-verified (% of secrets)": True,
    "M7 Scanner coverage (%)": True,
    "M8 AI cost per remediation (USD, monthly)": False,
    "M9 Posture score (0-100)": True,
}

st.set_page_config(page_title="Cycode Security Metrics", layout="wide")


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def parse_report(text: str) -> dict[str, pd.DataFrame]:
    """Split the stacked CSV ('## name' header, table, blank line) into frames."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in text.lstrip("﻿").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    frames = {}
    for name, lines in sections.items():
        body = "\n".join(lines).strip()
        if body:
            frames[name] = pd.read_csv(io.StringIO(body))
    return frames

def detail(frames: dict, metric: str, dimension: str) -> pd.DataFrame:
    df = frames.get(f"{metric} detail")
    if df is None or df.empty or "dimension" not in df:
        return pd.DataFrame()
    out = df[df["dimension"] == dimension].copy()
    if HIDE_UNMAPPED and "group" in out:
        out = out[out["group"].astype(str).str.lower() != UNMAPPED_LABEL.lower()]
    return out

def fmt(value, digits: int = 1) -> str:
    if pd.isna(value):
        return "-"
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.{digits}f}"

def status_badge(frames: dict, metric: str) -> str:
    df = frames.get(f"{metric} detail")
    if df is None or "status" not in df or df.empty:
        return "no data"
    counts = df["status"].value_counts()
    return ", ".join(f"{k}: {v}" for k, v in counts.items())

def add_background_image(main_image_url: str) -> None:
    """
    Set a full-page background image with a dark overlay for readability.
    URL must point directly at an image file (.jpg/.png/.webp/…), not HTML.
    """
    st.markdown(
        f"""
        <style>
        [data-testid="stAppViewContainer"] {{
            background-image:
                linear-gradient(rgba(14, 17, 22, 0.78), rgba(14, 17, 22, 0.78)),
                url("{main_image_url}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
        }}
        </style>
        """,
        unsafe_allow_html=True,
)


# ----------------------------------------------------------------------------
# Sidebar
# ----------------------------------------------------------------------------
st.sidebar.image(
        "https://mms.businesswire.com/media/20240429590822/en/2112506/4/Tempo-logo-color.jpg",
        width=200,
        caption="Tempo Software Inc.",
    )
st.sidebar.title("Cycode metrics")
# Ecoscanner (Jira tickets per marketplace app) has its own view: different units, never added to Cycode.
SOURCE = st.sidebar.radio("Source", ["Cycode", "Ecoscanner"], horizontal=True)
if SOURCE == "Ecoscanner":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cycode.dashboard.ecoscanner_view import render as render_ecoscanner
    render_ecoscanner(REPORT_DIR, parse_report)
    st.stop()
files = sorted(
    (p for p in REPORT_DIR.glob("cycode_metrics_*.csv") if not p.stem.endswith("_detail")),
    key=lambda p: p.stat().st_mtime, reverse=True,
)
uploaded = st.sidebar.file_uploader("Upload a metrics CSV", type="csv")
uploaded_detail = st.sidebar.file_uploader("Upload the matching _detail CSV", type="csv")
detail_text = ""
if uploaded is not None:
    text, source = uploaded.getvalue().decode("utf-8-sig"), uploaded.name
    if uploaded_detail is not None:
        detail_text = uploaded_detail.getvalue().decode("utf-8-sig")
elif files:
    choice = st.sidebar.selectbox("Report", files, format_func=lambda p: p.name)
    text, source = choice.read_text(encoding="utf-8-sig"), choice.name
    sibling = choice.with_name(choice.stem + "_detail.csv")
    if sibling.exists():
        detail_text = sibling.read_text(encoding="utf-8-sig")
else:
    st.error(f"No report found in {REPORT_DIR}. Run `python cycode_pipeline.py --date <date>` first.")
    st.stop()

frames = parse_report(text)
if detail_text:
    frames.update(parse_report(detail_text))
else:
    st.sidebar.warning("No *_detail.csv found: most charts need it. Re-run the pipeline.")
dimension = st.sidebar.radio("Group by", DIMENSIONS, index=0)
hide_empty = st.sidebar.checkbox("Hide groups with no open findings", value=True)
HIDE_UNMAPPED = st.sidebar.checkbox(
    "Hide 'Unmapped' group (experiment)", value=False,
    help="Removes the Unmapped group from the charts, tables and the headline numbers. The headline "
         "then shows how far each figure moves compared with keeping Unmapped (reference only).")
st.sidebar.caption(f"Source: {source}")

score = frames.get(f"Scorecard {dimension}")
if score is None or score.empty:
    st.error(f"The report has no 'Scorecard {dimension}' section.")
    st.stop()
score = score.set_index(score.columns[0])
if hide_empty and "Open findings" in score:
    score = score[score["Open findings"].fillna(0) > 0]
if HIDE_UNMAPPED:
    _hidden = score[score.index.astype(str).str.lower() == UNMAPPED_LABEL.lower()]
    score = score.drop(_hidden.index)
    if len(_hidden):
        st.sidebar.info(f"Hidden: {int(_hidden['Open findings'].fillna(0).sum()):,} open findings in Unmapped.")

# ----------------------------------------------------------------------------
# Header + KPIs
# ----------------------------------------------------------------------------
@st.dialog("Insights")
def show_popup(insights: list[str]):
    st.caption("Most important first. The full list is under the title on the page.")
    for insight in insights:
        st.markdown(f"- {insight}")
    # render_next_steps("popup")
    if st.button("Close", key="insights_close"):
        st.rerun()


# def render_next_steps(key: str) -> None:
#     """
#     'What should we do next?' button: an AI opinion on the insights above it, with a rule-based
#     playbook as the fallback. Runs only when clicked, once per report and grouping (the answer is
#     kept in session state), and sends only aggregate numbers and group names.
#     """
#     state_key = f"next_steps_{source}_{dimension}"
#     st.caption("Sends this week's aggregate numbers and group names (no finding text) to the model.")
#     if st.button("What should we do next? (AI opinion)", key=f"next_steps_btn_{key}"):
#         with st.spinner("Working out next steps..."):
#             st.session_state[state_key] = recommend_next_steps(
#                 anomalies, {"report": source, "compared_with": previous_label, "grouped_by": dimension})
#     result = st.session_state.get(state_key)
#     if result:
#         st.markdown(result["text"])
#         st.caption(f"Source: {result['source']}. An opinion from one week's aggregates; check the data caveats before acting.")

st.title("Cycode Security Metrics Dashboard")
st.caption(f"Report: {source}  |  Grouped by {dimension}  |  Cycode is the source of truth for resolution")

m3_all = frames.get("M3 detail", pd.DataFrame())
m4_all = frames.get("M4 detail", pd.DataFrame())
m5_all = frames.get("M5 detail", pd.DataFrame())


def first_value(df: pd.DataFrame, column: str):
    if df.empty or column not in df or df[column].dropna().empty:
        return float("nan")
    return df[column].dropna().iloc[0]

def _group_rows(df: pd.DataFrame, drop_unmapped: bool) -> pd.DataFrame:
    """Rows of one metric detail for the selected grouping; optionally without Unmapped."""
    if df.empty or "dimension" not in df:
        return pd.DataFrame()
    out = df[df["dimension"] == dimension]
    if drop_unmapped:
        out = out[out["group"].astype(str).str.lower() != UNMAPPED_LABEL.lower()]
    return out


def org_headline(drop_unmapped: bool) -> dict:
    """
    Org-level headline numbers, optionally without the Unmapped group.

    Recomputed from the per-group rows of the selected grouping, so they equal the
    pipeline's org figures when Unmapped is kept (Project and Team groupings
    reproduce them exactly):
      noise      = distinct noise issues / distinct open issues
      mttr       = fixed-issue weighted mean of the group means
      hygiene    = 100 * (1 - SLA-breached actionable issues / actionable issues)
    """
    out = {}
    m4 = _group_rows(m4_all, drop_unmapped)
    if not m4.empty and "issues" in m4 and m4["issues"].sum():
        out["noise"] = 100 * m4["noise_issues"].sum() / m4["issues"].sum()
    m3 = _group_rows(m3_all, drop_unmapped)
    # Empty M3 sections (no Fixed findings with a closing time) have no ttr_* columns.
    if not m3.empty and {"ttr_days_mean", "ttr_days_n"}.issubset(m3.columns):
        m3 = m3.dropna(subset=["ttr_days_mean", "ttr_days_n"])
        if not m3.empty and m3["ttr_days_n"].sum():
            out["mttr"] = (m3["ttr_days_mean"] * m3["ttr_days_n"]).sum() / m3["ttr_days_n"].sum()
    m5 = _group_rows(m5_all, drop_unmapped)
    if not m5.empty and "n" in m5 and m5["n"].sum():
        out["hygiene"] = 100 * (1 - m5["sla_breached_count"].sum() / m5["n"].sum())
    return out


def _kpi(column, label: str, value: float, with_unmapped: float, suffix: str = "") -> None:
    """Show a headline value; when Unmapped is hidden, show the value that includes it as the reference."""
    shown = f"{fmt(value)}{suffix}" if pd.notna(value) else "-"
    if HIDE_UNMAPPED and _has_unmapped and pd.notna(value) and pd.notna(with_unmapped):
        diff = value - with_unmapped
        column.metric(label, shown, delta=f"{diff:+,.1f} vs incl. Unmapped ({fmt(with_unmapped)}{suffix})",
                      delta_color="off")
    else:
        column.metric(label, shown)


import re as _re
from datetime import datetime as _dt

STATE_DIR = Path(__file__).resolve().parent.parent / "state"  # weekly digest history (optional)


def _report_date(name: str):
    match = _re.search(r"(\d{2}-[A-Za-z]{3}-\d{4})", str(name))
    try:
        return _dt.strptime(match.group(1), "%d-%b-%Y") if match else None
    except ValueError:
        return None


def _previous_report(current_name: str):
    """The newest report dated before the current one (so a missing week still compares with the last one there is)."""
    current_date = _report_date(current_name)
    if current_date is None:
        return None, None
    earlier = [(d, p) for p in files if (d := _report_date(p.name)) is not None and d < current_date]
    if not earlier:
        return None, None
    date, path = max(earlier, key=lambda item: item[0])
    return date, path


@st.cache_data(show_spinner=False)
def _scorecard_from(path_text: str, dim: str) -> pd.DataFrame:
    return parse_report(Path(path_text).read_text(encoding="utf-8-sig")).get(f"Scorecard {dim}", pd.DataFrame())


@st.cache_data(show_spinner=False)
def _history(path_text: str, modified: float) -> pd.DataFrame:
    return pd.read_csv(path_text, dtype={"snapshot_date": str})


# Weekly insights: this report's scorecard against the previous report's. Never allowed to stop the dashboard.
insight_lines: list[str] = []
anomalies: list[dict] = []
previous_label = None
try:
    current_date = _report_date(source)
    previous_date, previous_path = _previous_report(source) if uploaded is None else (None, None)
    previous_card = _scorecard_from(str(previous_path), dimension) if previous_path is not None else None
    history_path = STATE_DIR / "metrics_history.csv"
    history = _history(str(history_path), history_path.stat().st_mtime) if history_path.exists() else None
    anomalies = identify_anomalies(frames.get(f"Scorecard {dimension}"), previous_card, dimension, history,
                                   current_date.strftime("%Y-%m-%d") if current_date else None)
    insight_lines = attain_insights(anomalies)
    previous_label = previous_date.strftime("%d-%b-%Y") if previous_date else None
except Exception as exc:  # noqa: BLE001
    st.sidebar.warning(f"Insights unavailable: {type(exc).__name__}: {str(exc)[:120]}")

if anomalies or insight_lines:
    _needs_attention = [a for a in anomalies if a["severity"] == "high" or a["kind"] == "data"]
    _worse = [a for a in anomalies if a["kind"] == "change" and a.get("direction") != "better"
              and a["severity"] in ("high", "medium") and not a.get("baseline_shift")]
    _headline = (f"{len(_needs_attention)} item(s) need attention vs {previous_label or 'the previous report'}"
                 if _needs_attention else f"Nothing urgent vs {previous_label or 'the previous report'}")
    _box = st.error if any(a["severity"] == "high" for a in anomalies) else (
        st.warning if _needs_attention or _worse else st.info)
    _box(f"**This week's insights:** {_headline}. " + (insight_lines[0] if insight_lines else ""))
    with st.expander(f"What changed or looks unusual ({len(anomalies)})", expanded=bool(_needs_attention)):
        for line in insight_lines:
            st.markdown(f"- {line}")
        st.caption(f"Compared with {previous_label}. Thresholds are placeholders (ANOMALY_RULES in cycode_pipeline.py)."
                   if previous_label else "No earlier report to compare with.")
        # render_next_steps("page")
    _popup_key = f"insights_popup_{source}_{dimension}"
    if st.sidebar.button("Show insights popup", key="insights_button") or (
            _needs_attention and not st.session_state.get(_popup_key)):
        st.session_state[_popup_key] = True  # open once per report; the button reopens it
        show_popup(insight_lines)
_all_g = org_headline(False)
_no_g = org_headline(True)
_has_unmapped = bool(len(_group_rows(m5_all, False)) - len(_group_rows(m5_all, True))) or \
    bool(len(_group_rows(m4_all, False)) - len(_group_rows(m4_all, True)))
# Without the toggle the pipeline's own org figures are shown, untouched.
_use = _no_g if (HIDE_UNMAPPED and _has_unmapped) else {}
_org = lambda key, col, df: _use.get(key, first_value(df, col))  # noqa: E731

k1, k2, k3, k4, k5 = st.columns(5)
_open_all = frames.get(f"Scorecard {dimension}")
_open_all = _open_all.set_index(_open_all.columns[0]) if _open_all is not None and not _open_all.empty else score
_act_incl = _open_all["M1 Actionable High/Crit open"].sum()
_open_incl = _open_all["Open findings"].sum()
if HIDE_UNMAPPED:
    k1.metric("Open findings", fmt(score["Open findings"].sum()),
              delta=f"{score['Open findings'].sum() - _open_incl:+,.0f} vs incl. Unmapped ({fmt(_open_incl)})",
              delta_color="off")
    k2.metric("Actionable High/Critical", fmt(score["M1 Actionable High/Crit open"].sum()),
              delta=f"{score['M1 Actionable High/Crit open'].sum() - _act_incl:+,.0f} vs incl. Unmapped ({fmt(_act_incl)})",
              delta_color="off")
else:
    k1.metric("Open findings", fmt(score["Open findings"].sum()))
    k2.metric("Actionable High/Critical", fmt(score["M1 Actionable High/Crit open"].sum()))
_kpi(k3, "Noise rate (org)", _org("noise", "general_issue_noise_rate", m4_all),
     first_value(m4_all, "general_issue_noise_rate"), "%")
_kpi(k4, "Mean time to remediate (days)", _org("mttr", "general_ttr_days", m3_all),
     first_value(m3_all, "general_ttr_days"))
_kpi(k5, "Hygiene score (org)", _org("hygiene", "general_hygiene_score", m5_all),
     first_value(m5_all, "general_hygiene_score"))
if HIDE_UNMAPPED and not _has_unmapped:
    st.caption(f"No 'Unmapped' group in this grouping ({dimension}), so the headline is unchanged.")

tabs = st.tabs([
    "Scorecard", "Backlog (M1)", "Remediation (M3)", "Noise (M4)", "Age (M5)",
    "AI & cost (M6, M8)", "Coverage (M7)", "Posture (M9)", "Extras (X)", "Caveats", "Flow & SLA",
])

# ----------------------------------------------------------------------------
# Scorecard heatmap
# ----------------------------------------------------------------------------
with tabs[0]:
    st.subheader(f"All metrics side by side, by {dimension}")
    st.caption("Green is better, red is worse, within each column. Blank means no data for that group.")
    cols = [c for c in HIGHER_IS_BETTER if c in score.columns]
    values = score[cols]
    scaled = values.copy()
    for c in cols:
        lo, hi = values[c].min(), values[c].max()
        norm = (values[c] - lo) / (hi - lo) if pd.notna(hi) and hi != lo else values[c] * 0 + 0.5
        scaled[c] = norm if HIGHER_IS_BETTER[c] else 1 - norm
    text_vals = values.apply(lambda col: col.map(fmt))
    fig = go.Figure(go.Heatmap(
        z=scaled.values, x=[c.replace(" (", "<br>(") for c in cols], y=list(values.index),
        text=text_vals.values, texttemplate="%{text}", colorscale="RdYlGn",
        zmin=0, zmax=1, showscale=False, hoverongaps=False, xgap=2, ygap=2,
    ))
    fig.update_layout(height=max(320, 48 * len(values) + 140), yaxis_autorange="reversed",
                      xaxis_side="top", margin=dict(l=10, r=10, t=110, b=10))
    st.plotly_chart(fig, use_container_width=True)
    st.dataframe(score, use_container_width=True)
    st.download_button("Download this report CSV", text, file_name=source, mime="text/csv")

# ----------------------------------------------------------------------------
# M1
# ----------------------------------------------------------------------------
with tabs[1]:
    st.subheader("Actionable open High/Critical findings")
    st.caption("Open findings in the Actionable tier (High/Critical risk, score >= 70, severity >= Medium).")
    d = score[["Open findings", "M1 Actionable High/Crit open"]].dropna(how="all").reset_index()
    d.columns = [dimension, "Open findings", "Actionable High/Critical"]
    c1, c2 = st.columns(2)
    c1.plotly_chart(px.bar(d.sort_values("Actionable High/Critical"), x="Actionable High/Critical",
                           y=dimension, orientation="h", text="Actionable High/Critical",
                           title="Actionable High/Critical open"), use_container_width=True)
    d["Actionable share (%)"] = (100 * d["Actionable High/Critical"] / d["Open findings"]).round(1)
    c2.plotly_chart(px.bar(d.sort_values("Open findings"), x="Open findings", y=dimension,
                           orientation="h", text="Open findings", title="Total open backlog",
                           color_discrete_sequence=["#9aa5b1"]), use_container_width=True)
    st.dataframe(d, use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# M3
# ----------------------------------------------------------------------------
with tabs[2]:
    st.subheader("Time to remediate by severity")
    st.caption("Only findings Cycode closed as Fixed, linked to the audit log. Bars show the median; "
               "the line shows the 90th percentile. Loop is skewed by bulk CI/CD closures.")
    d = detail(frames, "M3", dimension)
    if not d.empty and "ttr_days_median" in d.columns:
        d = d[d["ttr_days_median"].notna()]
    if d.empty or "ttr_days_median" not in d.columns:
        st.info("No MTTR data for this grouping (needs enough Fixed findings with a known closing time).")
    else:
        fig = px.bar(d, x="group", y="ttr_days_median", color="severity", barmode="group",
                     labels={"group": dimension, "ttr_days_median": "Median days to fix"},
                     hover_data=["ttr_days_mean", "ttr_days_p90", "ttr_days_n"])
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(d[["group", "severity", "ttr_days_mean", "ttr_days_median", "ttr_days_p90", "ttr_days_n"]],
                     use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# M4
# ----------------------------------------------------------------------------
with tabs[3]:
    st.subheader("Noise: what share of the backlog is not worth triaging")
    d = detail(frames, "M4", dimension)
    if d.empty:
        st.info("No noise data.")
    else:
        d = d.sort_values("total", ascending=False)
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(d.sort_values("noise_rate_issues"), x="noise_rate_issues", y="group", orientation="h",
                               text="noise_rate_issues", labels={"noise_rate_issues": "Noise rate (%)", "group": dimension},
                               title="Noise rate"), use_container_width=True)
        c2.plotly_chart(px.bar(d.sort_values("top5_policy_share_pct"), x="top5_policy_share_pct", y="group",
                               orientation="h", labels={"top5_policy_share_pct": "Top 5 policies (% of findings)",
                                                       "group": dimension},
                               title="Concentration: top 5 policies"), use_container_width=True)
        st.caption("Tuning a handful of policies removes most of the noise where concentration is high.")
        st.dataframe(d[["group", "total", "noise_count", "noise_rate_issues", "top_policy",
                        "top_policy_share_pct", "top_noise_policies"]], use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# M5
# ----------------------------------------------------------------------------
with tabs[4]:
    st.subheader("Vulnerability age and SLA hygiene")
    st.caption("Age counts from the first Cycode scan (26-Aug), so it measures time in Cycode, not time in code. "
               "SLA days are placeholders.")
    d = detail(frames, "M5", dimension)
    if d.empty:
        st.info("No age data.")
    else:
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(d.sort_values("sla_breached_count"), x="sla_breached_count", y="group",
                               orientation="h", text="sla_breached_count",
                               labels={"sla_breached_count": "SLA breaches", "group": dimension},
                               title="SLA breaches"), use_container_width=True)
        c2.plotly_chart(px.bar(d.sort_values("hygiene_score"), x="hygiene_score", y="group", orientation="h",
                               range_x=[0, 100], text="hygiene_score",
                               labels={"hygiene_score": "Hygiene score (0-100)", "group": dimension},
                               title="Hygiene score (higher is better)"), use_container_width=True)
        fig = go.Figure()
        fig.add_bar(x=d["group"], y=d["detection_age_days"], name="Median age")
        fig.add_scatter(x=d["group"], y=d["detection_age_days_p90"], name="90th percentile", mode="markers+lines")
        fig.update_layout(title="Detection age (days)", yaxis_title="days")
        st.plotly_chart(fig, use_container_width=True)

# ----------------------------------------------------------------------------
# M6 + M8
# ----------------------------------------------------------------------------
with tabs[5]:
    st.subheader("AI leverage")
    d6 = detail(frames, "M6", dimension)
    if d6.empty:
        st.info("No AI leverage data.")
    else:
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(d6.sort_values("ai_verified_pct"), x="ai_verified_pct", y="group", orientation="h",
                               text="ai_verified_pct", range_x=[0, 100],
                               labels={"ai_verified_pct": "AI-verified (% of secrets)", "group": dimension},
                               title="Secrets verified by AI"), use_container_width=True)
        c2.plotly_chart(px.bar(d6.sort_values("filtered_by_ai_context"), x="filtered_by_ai_context", y="group",
                               orientation="h", text="filtered_by_ai_context",
                               labels={"filtered_by_ai_context": "Findings", "group": dimension},
                               title="Findings filtered by AI context"), use_container_width=True)
        st.caption("Auto-triage and reachability are blank until audit actor IDs are mapped to people/service accounts.")

    st.subheader("Remediations vs AI cost")
    st.warning(PLACEHOLDER_NOTE + " Treat cost figures as illustrative until real spend arrives.")
    d8 = detail(frames, "M8", dimension)
    if d8.empty:
        st.info("No remediation/cost data.")
    else:
        period = st.radio("Period", ["week", "month", "quarter"], index=1, horizontal=True)
        p = d8[d8["period"] == period]
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(p, x="group", y="avg_remediations",
                               labels={"avg_remediations": f"Avg remediations per {period}", "group": dimension},
                               title=f"Remediations per {period}"), use_container_width=True)
        c2.plotly_chart(px.bar(p.dropna(subset=["cost_per_remediation"]), x="group", y="cost_per_remediation",
                               labels={"cost_per_remediation": "USD per remediation", "group": dimension},
                               title="Cost per remediation (placeholder cost)"), use_container_width=True)
        st.dataframe(p[["group", "cost", "cost_share_pct", "avg_remediations", "cost_per_remediation"]],
                     use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# M7
# ----------------------------------------------------------------------------
with tabs[6]:
    st.subheader("Scanner coverage by project")
    st.caption("Repos expected (product_map.csv) vs. repos seen in the Cycode repository inventory. "
               "Project view only.")
    d = detail(frames, "M7", "Project")
    if d.empty:
        st.info("No coverage data (needs product_map.csv and a repository inventory export).")
    else:
        st.plotly_chart(px.bar(d.sort_values("coverage_pct"), x="coverage_pct", y="group", orientation="h",
                               text="coverage_pct", range_x=[0, 100],
                               labels={"coverage_pct": "Coverage (%)", "group": "Project"}),
                        use_container_width=True)
        st.dataframe(d[["group", "coverage_pct", "expected_repos", "scanned_repos"]],
                     use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# M9
# ----------------------------------------------------------------------------
with tabs[7]:
    st.subheader("Risk posture")
    d = detail(frames, "M9", dimension)
    if d.empty:
        st.info("No posture data.")
    else:
        st.caption("Exposure = risk level weight x risk score x triage tier, per repository. "
                   "Score = 100 / (1 + exposure per repo / median exposure per repo): 50 is the typical group, "
                   "higher is better, and it is relative to the other groups shown. "
                   "Bars use a log scale because exposure differs by orders of magnitude; labels show the score.")
        fig = px.bar(d.sort_values("norm_exposure"), x="norm_exposure", y="group", orientation="h",
                     log_x=True, text="posture_score",
                     labels={"norm_exposure": "Exposure per repo (log scale)", "group": dimension},
                     hover_data=["raw_exposure", "repos", "top_policies"])
        st.plotly_chart(fig, use_container_width=True)
        st.dataframe(d[["group", "posture_score", "raw_exposure", "norm_exposure", "repos", "top_policies"]],
                     use_container_width=True, hide_index=True)

# ----------------------------------------------------------------------------
# Extras
# ----------------------------------------------------------------------------
with tabs[8]:
    st.subheader("Additional metrics")
    x16 = frames.get(f"X1-X6 by {dimension}") if dimension in ("Project", "Team") else None
    if x16 is not None and not x16.empty:
        x16 = x16.set_index(x16.columns[0])
        body = x16.drop(index="TOTAL", errors="ignore")
        c1, c2 = st.columns(2)
        c1.plotly_chart(px.bar(body.reset_index(), x=body.index.name, y=["actionable_rows", "actionable_unique_issues"],
                               barmode="group", title="X1 Actionable rows vs unique issues"),
                        use_container_width=True)
        c2.plotly_chart(px.bar(body.reset_index(), x=body.index.name, y="actionable_sca_fix_available_pct",
                               title="X2 Actionable SCA with a fix available (%)"), use_container_width=True)
        st.dataframe(x16, use_container_width=True)
    else:
        st.info("X1-X6 are available for Project and Team grouping.")
    x7 = frames.get("X7 actionable by category")
    if x7 is not None and not x7.empty:
        x7 = x7.set_index(x7.columns[0])
        body = x7.drop(index="TOTAL", errors="ignore").drop(columns="TOTAL", errors="ignore")
        st.plotly_chart(px.bar(body.reset_index().melt(id_vars=x7.index.name), x=x7.index.name, y="value",
                               color="variable", title="X7 Actionable findings by category",
                               labels={"value": "Findings", "variable": "Category"}), use_container_width=True)
    x8 = frames.get("X8 triage activity")
    if x8 is not None and not x8.empty:
        x8 = x8.set_index(x8.columns[0])
        st.plotly_chart(px.bar(x8.reset_index(), x=x8.index.name,
                               y=["automated", "human_changes", "config_changes"], barmode="stack",
                               title="X8 Weekly triage activity (audit log)"), use_container_width=True)
        st.caption("Automation share reads 0% until audit actor IDs are mapped to service accounts.")

# ----------------------------------------------------------------------------
# Caveats
# ----------------------------------------------------------------------------
with tabs[9]:
    st.subheader("Data caveats and metric status")
    notes = frames.get("Notes")
    if notes is not None:
        for line in notes.iloc[:, 0].dropna():
            st.markdown(f"- {line}")
    st.markdown("**Metric status in this report**")
    st.table(pd.DataFrame(
        [{"Metric": m, "Status": status_badge(frames, m)} for m in
         ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "M9"]]
    ))
    st.markdown("- M2 (backlog trend) needs a previous snapshot, so it is not charted yet.")

# ----------------------------------------------------------------------------
# Flow & SLA (X14-X16)
# ----------------------------------------------------------------------------
with tabs[10]:
    st.subheader("Issues opened vs resolved per day")
    flow = frames.get("X14 daily flow by Project" if dimension == "Project" else "X14 daily flow")
    flow_all = frames.get("X14 daily flow")
    if flow_all is None or flow_all.empty:
        st.info("No X14 data in this report. Re-run the pipeline.")
    else:
        groups = ["All"]
        by_project = frames.get("X14 daily flow by Project")
        if by_project is not None and not by_project.empty:
            groups += sorted(by_project["group"].astype(str).unique())
        pick = st.selectbox("Product line", groups, key="flow_group")
        f = flow_all if pick == "All" else by_project[by_project["group"].astype(str) == pick]
        f = f.copy()
        f["date"] = pd.to_datetime(f["date"])
        window = st.slider("Last N days", 8, max(15, len(f)), min(90, max(15, len(f))), key="flow_days")
        f = f.tail(window)
        f["resolved_neg"] = -f["resolved"]
        fig = go.Figure()
        fig.add_bar(x=f["date"], y=f["opened"], name="Opened", marker_color="#d1495b")
        fig.add_bar(x=f["date"], y=f["resolved_neg"], name="Resolved", marker_color="#2a9d8f",
                    customdata=f["resolved"], hovertemplate="Resolved: %{customdata}<extra></extra>")
        fig.add_scatter(x=f["date"], y=f["net"].rolling(7, min_periods=1).mean(), name="Net (7-day avg)",
                        line=dict(color="white", width=2))
        fig.update_layout(barmode="relative", height=420, yaxis_title="Issues per day (resolved below zero)",
                          margin=dict(l=10, r=10, t=30, b=10), legend=dict(orientation="h"))
        st.plotly_chart(fig, use_container_width=True)
        fig2 = go.Figure()
        fig2.add_scatter(x=f["date"], y=f["open_backlog"], name="Open backlog (window-relative)", fill="tozeroy")
        fig2.update_layout(height=260, margin=dict(l=10, r=10, t=30, b=10), yaxis_title="Open issues")
        st.plotly_chart(fig2, use_container_width=True)
        st.caption("Per ISSUE, not per row. Opened = first detected that day; resolved = Resolved that day with a known "
                   "closing time (Fixed or otherwise); dismissals leave the backlog but are not counted as resolved. "
                   "A big first-scan spike is the initial import, not new risk. The backlog line starts at zero on the "
                   "first day shown, so read its slope, not its level.")

    st.subheader("SLA risk: which open issues will miss their SLA")
    sla = frames.get(f"X15 SLA risk by {dimension}") if dimension in ("Project", "Team") else None
    if sla is None or sla.empty:
        st.info("X15 is available for Project and Team grouping.")
    else:
        sla = sla.set_index(sla.columns[0])
        body = sla.drop(index="TOTAL", errors="ignore")
        st.plotly_chart(px.bar(body.reset_index(), x=body.index.name,
                               y=["breached", "high_risk_of_miss", "medium_risk_of_miss"], barmode="stack",
                               title="Open actionable issues by SLA outlook",
                               color_discrete_sequence=["#8b1e3f", "#d1495b", "#edae49"]),
                        use_container_width=True)
        st.dataframe(sla, use_container_width=True)
    risk = frames.get("X16 SLA at-risk issues")
    if risk is not None and not risk.empty:
        st.markdown("**Fix these first** (not yet breached, highest chance of missing)")
        st.dataframe(risk, use_container_width=True, hide_index=True)
    st.caption("Survival analysis: P(miss) = S(SLA) / S(age) from how long similar issues took to fix, with open and "
               "dismissed issues counted as censored. SLA days are placeholders. Strata with under 30 fixes fall back "
               "to a broader group. Dismissals are not independent of fixing, so treat the probability as a ranking.")
