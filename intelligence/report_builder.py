from pathlib import Path
from datetime import datetime
import json

FEATURES_DIR = Path("data/features")


def _current_timestamp():
    return datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")


def build_report(
    *,
    binary_path: str,
    metadata: dict,
    data_targets: dict,
    functions: list,
    call_graph: str,
    intents: list,
    risk: dict
) -> dict:
    """
    Single authoritative report writer.
    ALL artifacts are written ONLY here.
    """

    # -----------------------------
    # Ensure output directory
    # -----------------------------
    FEATURES_DIR.mkdir(parents=True, exist_ok=True)

    sample_name = Path(binary_path).name
    timestamp = _current_timestamp()

    report_dir = FEATURES_DIR / f"{sample_name}__{timestamp}"
    report_dir.mkdir(exist_ok=False)

    # -----------------------------
    # Metadata (forensics-grade)
    # -----------------------------
    full_metadata = {
        "binary_name": sample_name,
        "analysis_timestamp_utc": timestamp,
        "analysis_engine": "fti-static-radare2",
        "schema_version": "1.2",
        **metadata
    }

    # -----------------------------
    # Threat summary (minimal, high-signal)
    # -----------------------------
    threat_summary = {
        "verdict": risk["verdict"],
        "risk_score": risk["score"],
        "risk_rationale": risk.get("rationale", []),
        "behavioral_intent": _collapse_intents(intents),
        "critical_system_threat_functions": [
            f for f in functions if f.get("critical_system_threat")
        ]
    }

    # -----------------------------
    # Full analysis (RE / audit)
    # -----------------------------
    analysis = {
        "file_metadata": full_metadata,
        "data_targets": data_targets,
        "functions": functions,
        "intents": intents,
        "behavior_flow": risk.get("behavior_flow"),
        "obfuscation": risk.get("obfuscation"),
        "call_graph_dot": call_graph,
        "risk_assessment": risk
    }

    # -----------------------------
    # Write artifacts (ONLY here)
    # -----------------------------
    (report_dir / "metadata.json").write_text(
        json.dumps(full_metadata, indent=2)
    )

    (report_dir / "threat_summary.json").write_text(
        json.dumps(threat_summary, indent=2)
    )

    (report_dir / "analysis.json").write_text(
        json.dumps(analysis, indent=2)
    )

    # Optional: save call graph separately for tooling
    (report_dir / "callgraph.dot").write_text(call_graph)

    return {
        "report_path": str(report_dir),
        "verdict": threat_summary["verdict"],
        "risk_score": threat_summary["risk_score"]
    }


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
