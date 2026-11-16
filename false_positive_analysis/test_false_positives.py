from pathlib import Path

from cycode.cycode_pipeline import train_false_positive, predict_false_positive, load_all_violations

if __name__ == "__main__":
    all_df = load_all_violations(
            {
                "open": str("cycode/05-Nov-2026_api/Cycode - All violations - 05-Nov-2026.csv"),
                "closed": str("cycode/05-Nov-2026_api/Cycode - All violations (closed) - 05-Nov-2026.csv"),
            },
            "2026-11-05T00:00:00Z",
        )

    train_result = train_false_positive(all_df)
    predict_result = predict_false_positive(train_result["model"], all_df)
    # load_violations normalises Cycode headers (Policy -> policy, File Name -> file_path, …).
    cols = [
        "policy",
        "violation_category",
        "repository",
        "branch",
        "file_path",
        "is_false_positive_probability",
        "is_false_positive",
        "fp_protected",
        "fp_verify_first",
        "fp_review_candidate",
        "risk_score",
        "risk_level",
        "severity",
    ]
    # Medium/Low flagged issues are review candidates; flagged High/Critical issues are never auto-suppressed
    # but are the most valuable to verify, so both go into the file (the dashboard shows them separately).
    flagged = predict_result["fp_review_candidate"] | predict_result["fp_verify_first"]
    review = predict_result.loc[flagged, cols].sort_values(["fp_verify_first", "is_false_positive_probability"], ascending=False)
    print(review.head(40).to_string(index=False))
    print(
        f"\nopen issues scored: {len(predict_result):,} | "
        f"flagged FP: {int(predict_result['is_false_positive'].sum()):,} | "
        f"review candidates (Medium/Low): {int(predict_result['fp_review_candidate'].sum()):,} | "
        f"verify first (High/Critical): {int(predict_result['fp_verify_first'].sum()):,}"
    )
    out_path = Path("~/Documents/CyCode Project/false_positive_analysis/fp_review_candidates.csv").expanduser()
    review.to_csv(out_path, index=False)
    print(f"Wrote {len(review):,} rows to {out_path}")

