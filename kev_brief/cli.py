"""CLI entry point for kev-brief."""

from __future__ import annotations

import argparse
from pathlib import Path

from kev_brief.enrich import (
    filter_by_date,
    load_keywords,
    merge_epss,
    sort_for_report,
    tag_cloud_cicd,
)
from kev_brief.fetch import fetch_epss, fetch_kev, kev_to_dataframe
from kev_brief.mapping import apply_mapping, load_mapping_config
from kev_brief.report import build_context, convert_to_pdf, render_report, write_report

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="kev-brief",
        description="Generate a CTI-style weekly brief from CISA KEV and FIRST EPSS.",
    )
    parser.add_argument("--days", type=int, default=90, help="Look-back window in days (default: 90).")
    parser.add_argument(
        "--only-cloud",
        action="store_true",
        help="Drop entries that did not match the cloud/CI-CD keywords.",
    )
    parser.add_argument("--out", type=str, default="reports/", help="Output directory (default: reports/).")
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Also write a PDF with pandoc, if pandoc is installed.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Run fetch, filter, enrich, map, and render."""
    args = parse_args(argv)

    print("[1/6] Fetching CISA KEV catalog...")
    frame = kev_to_dataframe(fetch_kev())
    print(f"      Fetched: {len(frame)} entries")

    print(f"[2/6] Filtering to last {args.days} days...")
    frame = filter_by_date(frame, args.days)
    print(f"      Date-filtered: {len(frame)} entries")
    if frame.empty:
        print("WARNING: No entries in that window. Raise --days.")
        return

    print("[3/6] Tagging cloud/CI-CD entries...")
    keywords = load_keywords(str(PROJECT_ROOT / "config" / "keywords.yaml"))
    frame = tag_cloud_cicd(frame, keywords)
    cloud_count = int(frame["cloud_cicd"].sum())
    window_total = len(frame)
    print(f"      Cloud/CI-CD-tagged: {cloud_count} of {window_total}")
    if cloud_count < 5:
        print("      NOTE: that tag count is small. Raise --days or edit config/keywords.yaml.")

    if args.only_cloud:
        frame = frame.loc[frame["cloud_cicd"]].copy()
        print(f"      After --only-cloud: {len(frame)} entries")
        if frame.empty:
            print("WARNING: No cloud/CI-CD entries. Edit config/keywords.yaml or raise --days.")
            return

    print("[4/6] Fetching EPSS scores...")
    frame = merge_epss(frame, fetch_epss(frame["cveID"].tolist()))
    print(f"      EPSS scores found: {int(frame['epss'].notna().sum())} of {len(frame)}")

    print("[5/6] Applying ATT&CK mapping...")
    mapping = load_mapping_config(str(PROJECT_ROOT / "config" / "mapping.yaml"))
    frame = apply_mapping(frame, mapping)
    print(f"      Mapping confidence: {frame['mapping_confidence'].value_counts().to_dict()}")

    print("[6/6] Generating report...")
    frame = sort_for_report(frame)
    content = render_report(build_context(frame, args.days, window_total, cloud_count))
    md_path = write_report(content, Path(args.out))
    print(f"      Report written: {md_path}")

    if args.pdf:
        pdf_path = convert_to_pdf(md_path)
        if pdf_path:
            print(f"      PDF written: {pdf_path}")
    print("\nDone.")
