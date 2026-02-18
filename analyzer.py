import runner
import os

# -----------------------------
# Dynamic Analysis
# -----------------------------
from sandbox.dynamic_runner import run_with_strace
from sandbox.syscall_parser import parse_syscalls

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


SAMPLES_DIR = "data/samples"


# ==========================================================
# FULL HYBRID ANALYSIS
# ==========================================================

def analyze_binary(binary_path: str) -> dict:
    """
    Full static + dynamic malware analysis pipeline.
    Produces hybrid threat intelligence reports.
    """

    # -----------------------------
    # Initialize radare2
    # -----------------------------
    r2 = runner.RadareRunner(binary_path)
    r2.analyze()

    # -----------------------------
    # STATIC EXTRACTION
    # -----------------------------
    strings = extract_strings(r2)
    imports = extract_imports(r2)
    functions = extract_functions(r2)
    data_targets = extract_data_targets(strings)

    file_metadata = extract_file_metadata(binary_path)

    intents = classify_functions(functions)
    mapped_functions = map_functions(functions)

    obfuscation = detect_obfuscation(r2, binary_path)
    behavior_flow = build_behavior_flow(functions)

    call_graph = build_call_graph(functions)
    call_graph_dot = export_dot(call_graph)

    # -----------------------------
    # DYNAMIC ANALYSIS (STRACE)
    # -----------------------------
    try:
        strace_output = run_with_strace(binary_path)
        dynamic_findings = parse_syscalls(strace_output)
    except Exception as e:
        dynamic_findings = {}
        print(f"[!] Dynamic analysis failed: {e}")

    # -----------------------------
    # HYBRID RISK SCORING
    # -----------------------------
    risk = score_risk(
        intents=intents,
        obfuscation=obfuscation,
        behavior_flow=behavior_flow,
        dynamic_findings=dynamic_findings
    )

    # -----------------------------
    # BUILD REPORT (Single Exit)
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
        },
        dynamic_analysis={
            "syscall_findings": dynamic_findings,
            "behavioral_risk": risk.get("dynamic_component", 0),
            "behavioral_severity": risk.get("severity")
        }
    )

    r2.quit()
    return report


# ==========================================================
# BATCH ANALYSIS
# ==========================================================

def analyze_all_samples():
    results = {}

    if not os.path.exists(SAMPLES_DIR):
        print("Samples folder not found.")
        return results

    for filename in os.listdir(SAMPLES_DIR):
        sample_path = os.path.join(SAMPLES_DIR, filename)

        if not os.path.isfile(sample_path):
            continue

        print(f"\n[+] Hybrid Analyzing {filename}...")

        try:
            report = analyze_binary(sample_path)
            results[filename] = report
        except Exception as e:
            results[filename] = {"error": str(e)}

    return results
