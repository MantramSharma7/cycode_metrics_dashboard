"""
Ecoscanner view for the Cycode metrics dashboard.

cycode_dashboard.py calls render() when "Ecoscanner" is picked in the Source switch.
It reads the files written by `python3 ecoscanner_pipeline.py`:
    reports/ecoscanner_metrics_<date>.csv            scorecards, notes, extras X10-X12
    reports/ecoscanner_metrics_<date>_detail.csv     M1-M9 detail

Ecoscanner counts Jira TICKETS per marketplace app; Cycode counts code findings. The two
are shown apart on purpose and are never added together.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

DIMENSIONS = ["Project", "App", "Hosting"]
UNIT_NOTE = ("Ecoscanner counts Jira tickets for marketplace apps (not Cycode code findings). "
             "Severity is the Jira severity level and SLA is the Jira remediation due date.")

# True = higher is better, False = lower is better.
HIGHER_IS_BETTER = {
    "M1 Actionable High/Crit open": False,
    "M1 Open Medium (P3)": False,
    "M3 MTTR Medium (median days)": False,
    "M3 MTTR Low (median days)": False,
    "M3 MTTR all (median days)": False,
    "M4 Noise rate (%)": False,
    "M5 Median open age (days)": False,
    "M5 SLA breaches": False,
    "M5 Hygiene score (0-100)": True,
    "M8 Remediations per month": True,
    "M9 Posture score (0-100)": True,
}
SEVERITY_COLORS = {"Critical": "#B71C1C", "High": "#F57C00", "Medium": "#F9A825", "Low": "#90A4AE"}


def _fmt(value, digits: int = 1) -> str:
    if value is None or pd.isna(value):
        return "-"
    return f"{value:,.0f}" if float(value).is_integer() else f"{value:,.{digits}f}"


def _first(df: pd.DataFrame, column: str):
    if df is None or df.empty or column not in df or df[column].dropna().empty:
        return float("nan")
    return df[column].dropna().iloc[0]


def _detail(frames: dict, metric: str, dimension: str) -> pd.DataFrame:
    df = frames.get(f"{metric} detail")
    if df is None or df.empty or "dimension" not in df:
        return pd.DataFrame()
    return df[df["dimension"] == dimension].copy()


def _heatmap(score: pd.DataFrame) -> None:
    cols = [c for c in HIGHER_IS_BETTER if c in score.columns]
    values = score[cols]
    scaled = values.copy()
    for c in cols:
        lo, hi = values[c].min(), values[c].max()
        norm = (values[c] - lo) / (hi - lo) if pd.notna(hi) and hi != lo else values[c] * 0 + 0.5
        scaled[c] = norm if HIGHER_IS_BETTER[c] else 1 - norm
    fig = go.Figure(go.Heatmap(
        z=scaled.values, x=cols, y=[str(i) for i in values.index], colorscale="RdYlGn", zmin=0, zmax=1,
        showscale=False, text=values.map(lambda v: _fmt(v)).values, texttemplate="%{text}", xgap=2, ygap=2))
    fig.update_layout(height=max(260, 40 * len(values) + 120), margin=dict(l=10, r=10, t=10, b=10),
                      xaxis=dict(side="top", tickangle=-30), yaxis=dict(autorange="reversed"))
    st.plotly_chart(fig, use_container_width=True)


def render(report_dir: Path, parse_report: Callable[[str], dict]) -> None:
    files = sorted((p for p in report_dir.glob("ecoscanner_metrics_*.csv") if not p.stem.endswith("_detail")),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        st.error(f"No Ecoscanner report in {report_dir}. Run `python3 ecoscanner_pipeline.py --input <Jira export csv>` first.")
        st.stop()
    choice = st.sidebar.selectbox("Ecoscanner report", files, format_func=lambda p: p.name)
    frames = parse_report(choice.read_text(encoding="utf-8-sig"))
    sibling = choice.with_name(choice.stem + "_detail.csv")
    if sibling.exists():
        frames.update(parse_report(sibling.read_text(encoding="utf-8-sig")))
    else:
        st.sidebar.warning("No *_detail.csv found: most charts need it. Re-run ecoscanner_pipeline.py.")
    dimension = st.sidebar.radio("Group by", DIMENSIONS, index=0, key="eco_dimension")
    st.sidebar.caption(f"Source: {choice.name}")

    score = frames.get(f"Scorecard {dimension}")
    if score is None or score.empty:
        st.error(f"The report has no 'Scorecard {dimension}' section.")
        st.stop()
    score = score.set_index(score.columns[0])
    if "Open tickets" in score and st.sidebar.checkbox("Hide groups with no open tickets", value=False, key="eco_hide_empty"):
        score = score[score["Open tickets"].fillna(0) > 0]

    st.title("Ecoscanner marketplace security tickets")
    st.caption(f"Report: {choice.name}  |  Grouped by {dimension}  |  {UNIT_NOTE}")

    m3, m4, m5 = (frames.get(f"{k} detail", pd.DataFrame()) for k in ("M3", "M4", "M5"))
    link = frames.get("X12 Dependabot linkage by Project", pd.DataFrame())
    linked = link[link.iloc[:, 0] == "TOTAL"]["linked_pct"] if not link.empty else pd.Series(dtype=float)
    k = st.columns(6)
    k[0].metric("Open tickets", _fmt(score["Open tickets"].sum()))
    k[1].metric("Open High/Critical", _fmt(score["M1 Actionable High/Crit open"].sum()))
    k[2].metric("Median days to patch", _fmt(_first(m3[m3["severity"] == "All"] if not m3.empty else m3, "ttr_days_median")))
    k[3].metric("Noise rate", f"{_fmt(_first(m4, 'general_noise_rate'))}%")
    k[4].metric("SLA hygiene", _fmt(_first(m5, "general_hygiene_score")))
    k[5].metric("Dependabot linked", f"{_fmt(linked.iloc[0])}%" if len(linked) else "-")

    tabs = st.tabs(["Scorecard", "Backlog (M1, M2)", "Remediation (M3)", "Noise (M4)", "Age and SLA (M5)",
                    "Posture (M9)", "Extras (X10-X12)", "Caveats"])

    with tabs[0]:
        st.subheader(f"All metrics side by side, by {dimension}")
        st.caption("Green is better, red is worse, within each column. Blank means no data for that group.")
        _heatmap(score)
        st.dataframe(score, use_container_width=True)

    with tabs[1]:
        st.subheader("Open tickets by severity")
        d = _detail(frames, "M1", dimension)
        if d.empty:
            st.info("No backlog data.")
        else:
            long = d.melt(id_vars="group", value_vars=["open_critical", "open_high", "open_medium", "open_low"],
                          var_name="severity", value_name="tickets")
            long["severity"] = long["severity"].str.replace("open_", "").str.title()
            fig = px.bar(long, x="tickets", y="group", color="severity", orientation="h", color_discrete_map=SEVERITY_COLORS,
                         category_orders={"severity": ["Critical", "High", "Medium", "Low"]},
                         labels={"group": dimension})
            fig.update_layout(yaxis=dict(categoryorder="total ascending"))
            st.plotly_chart(fig, use_container_width=True)
            st.caption("No open ticket is above P3 (Medium) in this export, so the actionable High/Critical count is 0.")
        st.subheader("Open backlog by week")
        t = _detail(frames, "M2", dimension)
        if not t.empty:
            fig = px.line(t, x="week_ending", y="open_tickets", color="group", markers=True, labels={"week_ending": "Week ending"})
            st.plotly_chart(fig, use_container_width=True)
            st.caption("Rebuilt from each ticket's Created and Resolved dates.")

    with tabs[2]:
        st.subheader("Time to patch by severity")
        st.caption("Tickets closed as Patched, Created to Resolved. Duplicate, False Positive and Won't Fix are not remediation. "
                   "No Critical or High ticket has been patched, so only Medium and Low appear.")
        d = _detail(frames, "M3", dimension)
        d = d[(d["severity"] != "All") & d["ttr_days_median"].notna()] if not d.empty else d
        if d.empty:
            st.info("No patched tickets for this grouping.")
        else:
            fig = px.bar(d, x="group", y="ttr_days_median", color="severity", barmode="group", color_discrete_map=SEVERITY_COLORS,
                         labels={"group": dimension, "ttr_days_median": "Median days to patch"},
                         hover_data=["ttr_days_mean", "ttr_days_p90", "ttr_days_n"])
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(d[["group", "severity", "ttr_days_mean", "ttr_days_median", "ttr_days_p90", "ttr_days_n"]],
                         use_container_width=True, hide_index=True)

    with tabs[3]:
        st.subheader("Noise: tickets that were not real work")
        d = _detail(frames, "M4", dimension)
        if d.empty:
            st.info("No noise data.")
        else:
            long = d.melt(id_vars="group", value_vars=["duplicate", "false_positive", "wont_fix"], var_name="closed as",
                          value_name="tickets")
            long["closed as"] = long["closed as"].map({"duplicate": "Duplicate", "false_positive": "False Positive",
                                                       "wont_fix": "Won't Fix (accepted risk)"})
            c1, c2 = st.columns(2)
            c1.plotly_chart(px.bar(d.sort_values("noise_rate"), x="noise_rate", y="group", orientation="h", text="noise_rate",
                                   labels={"noise_rate": "Noise rate (%)", "group": dimension}, title="Noise rate"),
                            use_container_width=True)
            c2.plotly_chart(px.bar(long, x="tickets", y="group", color="closed as", orientation="h",
                                   labels={"group": dimension}, title="How tickets were closed without a patch"),
                            use_container_width=True)
            st.dataframe(d[["group", "total", "noise_tickets", "duplicate", "false_positive", "wont_fix", "noise_rate",
                            "accepted_rate", "top_noise_scanner"]], use_container_width=True, hide_index=True)
            st.caption("Noise = Duplicate + False Positive. Won't Fix is accepted risk and is not counted as noise.")

    with tabs[4]:
        st.subheader("Age of open tickets and SLA hygiene")
        d = _detail(frames, "M5", dimension)
        if d.empty:
            st.info("No open tickets in this grouping.")
        else:
            c1, c2 = st.columns(2)
            c1.plotly_chart(px.bar(d.sort_values("age_days_median"), x="age_days_median", y="group", orientation="h",
                                   text="age_days_median", labels={"age_days_median": "Median age (days)", "group": dimension},
                                   title="Median age of open tickets"), use_container_width=True)
            c2.plotly_chart(px.bar(d.sort_values("hygiene_score"), x="hygiene_score", y="group", orientation="h",
                                   range_x=[0, 100], text="hygiene_score",
                                   labels={"hygiene_score": "Hygiene score (0-100)", "group": dimension},
                                   title="SLA hygiene (higher is better)"), use_container_width=True)
            st.dataframe(d[["group", "age_days_median", "age_days_p90", "sla_breached_count", "tickets_with_due_date",
                            "no_due_date", "hygiene_score"]], use_container_width=True, hide_index=True)
            st.caption("Hygiene = 100 x (1 - overdue / open tickets with a Remediation Due Date). Due dates are Jira's own.")

    with tabs[5]:
        st.subheader("Risk posture")
        d = _detail(frames, "M9", dimension)
        if d.empty:
            st.info("No posture data.")
        else:
            st.plotly_chart(px.bar(d.sort_values("posture_score"), x="posture_score", y="group", orientation="h",
                                   range_x=[0, 100], text="posture_score",
                                   labels={"posture_score": "Posture score (0-100, higher is better)", "group": dimension}),
                            use_container_width=True)
            st.dataframe(d[["group", "posture_score", "raw_exposure", "norm_exposure", "apps", "top_checks"]],
                         use_container_width=True, hide_index=True)
            st.caption("Relative score: 50 is the typical group. Severity weights are placeholders.")

    with tabs[6]:
        urg = frames.get(f"X10 urgency by {dimension if dimension != 'Hosting' else 'Project'}")
        st.subheader("X10. Open tickets by urgency")
        if urg is None or urg.empty:
            st.info("No open tickets.")
        else:
            st.dataframe(urg, use_container_width=True, hide_index=True)
            st.caption("Overdue = due date passed; Severity P3+ = Medium or higher; Scheduled = future due date.")
        st.subheader("X11. Findings repeated across apps (fix once at the source)")
        rep = frames.get("X11 repeated findings")
        if rep is not None and not rep.empty:
            st.dataframe(rep, use_container_width=True, hide_index=True)
        st.subheader("X12. Dependabot linkage")
        if not link.empty:
            st.dataframe(link, use_container_width=True, hide_index=True)
        imp = frames.get("X12 Dependabot imputation")
        if imp is not None and not imp.empty:
            st.dataframe(imp, use_container_width=True, hide_index=True)
            st.caption("Imputed links follow the pattern (package, CVE, version group) learned from the manually linked sample "
                       "and are flagged in the imputed export's 'Dependabot Basis' column.")

    with tabs[7]:
        st.subheader("Caveats")
        notes = frames.get("Notes")
        if notes is not None:
            for line in notes.iloc[:, 0].dropna():
                st.markdown(f"- {line}")
        for key in ("M6", "M7"):
            blocked = frames.get(f"{key} detail")
            if blocked is not None and not blocked.empty:
                st.warning(f"{key}: {blocked['note'].iloc[0]}")
        if "Unmapped" in [str(i) for i in score.index]:
            st.warning("Some apps have no product line. Confirm them in ecoscanner_app_map.csv.")
