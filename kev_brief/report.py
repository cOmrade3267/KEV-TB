"""Render the Markdown brief and, optionally, a PDF via pandoc."""

from __future__ import annotations

import math
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
from jinja2 import Environment, FileSystemLoader

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _fmt_epss(val: object) -> str:
    """Format an EPSS score. Missing scores display as n/a."""
    if val is None:
        return "n/a"
    try:
        if pd.isna(val):
            return "n/a"
    except TypeError:
        return "n/a"
    number = float(val)  # type: ignore[arg-type]
    if math.isnan(number):
        return "n/a"
    return f"{number:.4f}"


def _cell(text: object, max_len: int = 80) -> str:
    """One-line table cell. Pipes are escaped so they do not break Markdown."""
    cleaned = " ".join(str(text).split()).replace("|", "\\|")
    if len(cleaned) <= max_len:
        return cleaned
    return cleaned[: max_len - 3] + "..."


def _ransomware_flag(val: object) -> str:
    """KEV uses the string 'Known' when a ransomware campaign is linked."""
    if isinstance(val, str) and val.strip().lower() == "known":
        return "Yes"
    return "No"


def _priority_top10(df: pd.DataFrame) -> pd.DataFrame:
    """Rank the brief: ransomware, then soonest due date, then cloud/CI-CD.

    EPSS is not a sort key. Missing due dates sort after real dates.
    """
    frame = df.copy()
    frame["_ransom"] = frame["knownRansomwareCampaignUse"].map(
        lambda value: str(value).strip().lower() == "known"
    )
    due = frame["dueDate"].astype(str).str.slice(0, 10)
    frame["_due"] = due.where(due.str.fullmatch(r"\d{4}-\d{2}-\d{2}"), "9999-99-99")
    frame["_cloud"] = frame["cloud_cicd"].fillna(False).astype(bool)
    ordered = frame.sort_values(
        ["_ransom", "_due", "_cloud"],
        ascending=[False, True, False],
        kind="mergesort",
    )
    return ordered.head(10)


def build_context(
    df: pd.DataFrame,
    days: int,
    window_total: int,
    window_cloud: int,
) -> dict:
    """Build template variables from the enriched frame.

    `window_total` and `window_cloud` are the date-window counts, before
    `--only-cloud` drops rows. Ransomware is counted on the rows in the brief.
    """
    now = datetime.now(timezone.utc)
    ransomware_count = int(
        df["knownRansomwareCampaignUse"]
        .map(lambda value: str(value).strip().lower() == "known")
        .sum()
    )
    vendor_counts = df["vendorProject"].value_counts().head(5)
    top_vendors = ", ".join(
        f"{vendor} ({count})" for vendor, count in vendor_counts.items()
    )
    scored = df.dropna(subset=["epss"])
    top_epss = [
        {"cveID": row["cveID"], "epss_fmt": _fmt_epss(row["epss"])}
        for _, row in scored.nlargest(5, "epss").iterrows()
    ]
    top10 = [
        {
            "cveID": row["cveID"],
            "vendor_product": f"{row['vendorProject']} / {row['product']}",
            "epss_fmt": _fmt_epss(row.get("epss")),
            "ransomware_flag": _ransomware_flag(row["knownRansomwareCampaignUse"]),
            "cloud_flag": "Yes" if row.get("cloud_cicd") else "No",
            "technique": f"{row.get('technique_id', '')} {row.get('technique_name', '')}".strip(),
            "dueDate": row.get("dueDate", ""),
        }
        for _, row in _priority_top10(df).iterrows()
    ]

    counts: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    names: dict[str, str] = {}
    for _, row in df.iterrows():
        technique_id = str(row.get("technique_id", ""))
        counts[technique_id] += 1
        names[technique_id] = str(row.get("technique_name", ""))
        examples.setdefault(technique_id, [])
        if len(examples[technique_id]) < 3:
            examples[technique_id].append(str(row["cveID"]))
    techniques = [
        {
            "technique": f"{technique_id} {names[technique_id]}".strip(),
            "count": count,
            "examples": ", ".join(examples[technique_id]),
        }
        for technique_id, count in counts.most_common()
    ]

    all_rows = [
        {
            "cveID": row["cveID"],
            "vendor_product": _cell(f"{row['vendorProject']} / {row['product']}", 40),
            "vulnerabilityName": _cell(row["vulnerabilityName"], 48),
            "epss_fmt": _fmt_epss(row.get("epss")),
            "cloud_flag": "Yes" if row.get("cloud_cicd") else "No",
            "ransomware_flag": _ransomware_flag(row["knownRansomwareCampaignUse"]),
            "technique_id": row.get("technique_id", ""),
            "mapping_confidence": row.get("mapping_confidence", ""),
            "dueDate": row.get("dueDate", ""),
            "requiredAction": _cell(row.get("requiredAction", ""), 70),
        }
        for _, row in df.iterrows()
    ]

    return {
        "report_date": now.strftime("%Y-%m-%d"),
        "start_date": (now - timedelta(days=days)).strftime("%Y-%m-%d"),
        "end_date": now.strftime("%Y-%m-%d"),
        "days": days,
        "total_count": window_total,
        "cloud_count": window_cloud,
        "shown_count": len(df),
        "ransomware_count": ransomware_count,
        "top_vendors": top_vendors or "n/a",
        "top_epss": top_epss,
        "top10": top10,
        "techniques": techniques,
        "all_rows": all_rows,
        "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
    }


def render_report(context: dict, template_dir: Path | None = None) -> str:
    """Render templates/brief.md.j2."""
    if template_dir is None:
        template_dir = PROJECT_ROOT / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        keep_trailing_newline=True,
    )
    return env.get_template("brief.md.j2").render(**context)


def write_report(content: str, out_dir: Path) -> Path:
    """Write reports/kev-brief-YYYY-MM-DD.md. Returns that path."""
    out_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out_path = out_dir / f"kev-brief-{date_str}.md"
    out_path.write_text(content, encoding="utf-8")
    return out_path


_LATEX_ENGINES = ("xelatex", "pdflatex", "lualatex")
_PDF_ENGINES = _LATEX_ENGINES + ("tectonic", "typst")


def convert_to_pdf(md_path: Path) -> Path | None:
    """Convert Markdown to PDF with pandoc. A missing tool is not a failure."""
    if shutil.which("pandoc") is None:
        print("NOTE: pandoc is not installed, so no PDF was written.")
        print("      The Markdown report is complete. Install pandoc and a PDF engine to use --pdf.")
        return None
    engine = next((name for name in _PDF_ENGINES if shutil.which(name)), None)
    if engine is None:
        print("NOTE: pandoc is installed, but no PDF engine was found.")
        print("      Install xelatex, pdflatex, lualatex, tectonic, or typst. The Markdown report is complete.")
        return None
    pdf_path = md_path.with_suffix(".pdf")
    command = ["pandoc", str(md_path), "-o", str(pdf_path), f"--pdf-engine={engine}"]
    if engine in _LATEX_ENGINES:
        command.extend(["-V", "geometry:margin=1in"])
    try:
        subprocess.run(command, check=True, capture_output=True)
        return pdf_path
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace")[:200]
        print(f"WARNING: pandoc failed ({detail}). The Markdown report was kept.")
        return None
