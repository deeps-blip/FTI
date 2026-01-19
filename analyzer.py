import runner

# -----------------------------
# Extractors
# -----------------------------
from extractors.strings import extract_strings
from extractors.imports import extract_imports
from extractors.functions import extract_functions
from extractors.data_targets import extract_data_targets

# -----------------------------
# Intelligence layers
# -----------------------------
from intelligence.intent_classifier import classify_functions
from intelligence.function_mapper import map_functions
from intelligence.obfuscation_detector import detect_obfuscation
from intelligence.behavior_flow import build_behavior_flow
from intelligence.risk_scorer import score_risk
from intelligence.graph_builder import build_call_graph, export_dot
from intelligence.file_metadata import extract_file_metadata
from intelligence.report_builder import build_report


def analyze_binary(binary_path: str) -> dict:
    """
    Full static malware analysis pipeline.
    Produces professional-grade threat intelligence reports.
    """

    # -----------------------------
    # Initialize radare2
    # -----------------------------
    r2 = runner.RadareRunner(binary_path)
    r2.analyze()

    # -----------------------------
    # Static extraction
    # -----------------------------
    strings = extract_strings(r2)
    imports = extract_imports(r2)
    functions = extract_functions(r2)
    data_targets = extract_data_targets(strings)

    # -----------------------------
    # File-level metadata
    # -----------------------------
    file_metadata = extract_file_metadata(binary_path)

    # -----------------------------
    # Function-level intelligence
    # -----------------------------
    intents = classify_functions(functions)
    mapped_functions = map_functions(functions)

    # -----------------------------
    # Obfuscation / packing detection
    # -----------------------------
    obfuscation = detect_obfuscation(r2, binary_path)

    # -----------------------------
    # Behavior flow & call graph
    # -----------------------------
    behavior_flow = build_behavior_flow(functions)
    call_graph = build_call_graph(functions)
    call_graph_dot = export_dot(call_graph)

    # -----------------------------
    # Risk assessment (behavior-driven)
    # -----------------------------
    risk = score_risk(
        intents=intents,
        obfuscation=obfuscation,
        behavior_flow=behavior_flow
    )

    # -----------------------------
    # Report generation (SINGLE EXIT POINT)
    # -----------------------------
    report = build_report(
        binary_path=binary_path,
        metadata={
            **file_metadata,
            "architecture": r2.cmdj("ij").get("bin", {}).get("arch"),
            "format": r2.cmdj("ij").get("bin", {}).get("format")
        },
        data_targets=data_targets,
        functions=mapped_functions,
        call_graph=call_graph_dot,
        intents=intents,
        risk={
            **risk,
            "obfuscation": obfuscation,
            "behavior_flow": behavior_flow
        }
    )

    # -----------------------------
    # Cleanup
    # -----------------------------
    r2.quit()
    return report
