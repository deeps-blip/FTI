from pathlib import Path
from datetime import datetime
import json

FEATURES_DIR = Path("data/features")


# ==========================================================
# TIMESTAMP
# ==========================================================

def _current_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")


# ==========================================================
# REPORT BUILDER
# ==========================================================

def build_report(
    *,
    binary_path: str,
    metadata: dict,
    data_targets: dict,
    functions: list,
    call_graph: str,
    intents: list,
    risk: dict,
    dynamic_analysis: dict | None = None
) -> dict:
    """
    Single authoritative report writer.
    ALL artifacts are written ONLY here.
    """

    # ----------------------------------------------------------
    # Ensure output directory
    # ----------------------------------------------------------
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    sample_name = Path(binary_path).name
    timestamp = _current_timestamp()

    report_dir = FEATURES_DIR / f"{sample_name}__{timestamp}"
    report_dir.mkdir(exist_ok=False)

    # ==========================================================
    # Metadata
    # ==========================================================

    full_metadata = {
        "binary_name": sample_name,
        "analysis_timestamp_utc": timestamp,
        "analysis_engine": "fti-hybrid-static-dynamic",
        "schema_version": "1.5",
        **metadata
    }

    # ==========================================================
    # Threat Summary
    # ==========================================================

    threat_summary = {
        "verdict": risk.get("verdict"),
        "risk_score": risk.get("score"),
        "severity": risk.get("severity"),
        "risk_model": risk.get("risk_model"),
        "risk_rationale": risk.get("rationale", []),
        "static_component": risk.get("static_component"),
        "dynamic_component": risk.get("dynamic_component"),
        "behavioral_intent": _collapse_intents(intents),
        "critical_system_threat_functions": [
            f for f in functions if f.get("critical_system_threat")
        ]
    }

    # ----------------------------------------------------------
    # Dynamic Summary
    # ----------------------------------------------------------
    if dynamic_analysis:

        findings = dynamic_analysis.get("syscall_findings", {})

        threat_summary["dynamic_behavior"] = {
            "behavioral_risk_score": dynamic_analysis.get("behavioral_risk"),
            "behavioral_severity": dynamic_analysis.get("behavioral_severity"),
            "observed_syscall_categories": [
                category for category, count in findings.items()
                if isinstance(count, int) and count > 0
            ],
            "raw_syscall_counts": findings,
            "behavior_explanations": dynamic_analysis.get("explanations", [])
        }

    # ==========================================================
    # Full Analysis (Deep View)
    # ==========================================================

    analysis = {
        "file_metadata": full_metadata,
        "data_targets": data_targets,
        "functions": functions,
        "intents": intents,
        "behavior_flow": risk.get("behavior_flow"),
        "obfuscation": risk.get("obfuscation"),
        "call_graph_dot": call_graph,
        "risk_assessment": risk,
        "dynamic_analysis": dynamic_analysis
    }

    # ==========================================================
    # Write Core Artifacts
    # ==========================================================

    (report_dir / "metadata.json").write_text(
        json.dumps(full_metadata, indent=2)
    )

    (report_dir / "threat_summary.json").write_text(
        json.dumps(threat_summary, indent=2)
    )

    (report_dir / "analysis.json").write_text(
        json.dumps(analysis, indent=2)
    )

    (report_dir / "functions.json").write_text(
        json.dumps(
            {
                "function_count": len(functions),
                "functions": functions
            },
            indent=2
        )
    )

    (report_dir / "callgraph.dot").write_text(call_graph)

    # ==========================================================
    # NEW: Separate Dynamic Dump
    # ==========================================================

    if dynamic_analysis:
        (report_dir / "dynamic_analysis.json").write_text(
            json.dumps(dynamic_analysis, indent=2)
        )

    # ==========================================================
    # Return Summary
    # ==========================================================

    return {
        "report_path": str(report_dir),
        "verdict": threat_summary["verdict"],
        "risk_score": threat_summary["risk_score"],
        "severity": threat_summary.get("severity")
    }


# ==========================================================
# INTENT COLLAPSER
# ==========================================================

def _collapse_intents(intents):
    summary = {}

    for item in intents:
        for purpose in item.get("purposes", []):
            summary[purpose] = summary.get(purpose, 0) + 1

    return {
        "observed_function_purposes": list(summary.keys()),
        "dominant_behaviors": [
            k for k, v in summary.items() if v >= 2
        ]
    }
