# ==========================================================
# BEHAVIORAL CATEGORY WEIGHTS (from risk_mapper)
# ==========================================================

CATEGORY_WEIGHTS = {
    "network": 3,
    "file_modification": 2,
    "process_injection": 5,
    "privilege": 4,
    "execution": 1
}


# ==========================================================
# BEHAVIORAL RISK CALCULATION
# ==========================================================

def calculate_behavioral_risk(findings):
    score = 0

    for category, count in findings.items():
        weight = CATEGORY_WEIGHTS.get(category, 0)
        score += weight * count

    return min(score, 100)


# ==========================================================
# SEVERITY CLASSIFICATION
# ==========================================================

def classify_severity(score):
    if score < 30:
        return "low"
    elif score < 60:
        return "medium"
    elif score < 80:
        return "high"
    else:
        return "critical"


# ==========================================================
# MAIN HYBRID RISK SCORER
# ==========================================================

def score_risk(
    intents,
    obfuscation,
    behavior_flow,
    dynamic_findings=None   # NEW (optional)
):
    """
    Hybrid static + behavioral risk scoring engine.
    """

    static_score = 0
    rationale = []

    # ------------------------------------------------
    # Static Intent-Based Scoring
    # ------------------------------------------------

    purposes = set()
    for i in intents:
        purposes.update(i.get("purposes", []))

    if "network_communication" in purposes:
        static_score += 30
        rationale.append("Active network communication detected")

    if "persistence" in purposes:
        static_score += 25
        rationale.append("Persistence mechanisms identified")

    if "credential_access" in purposes:
        static_score += 30
        rationale.append("Credential access behavior")

    if obfuscation.get("packed_or_obfuscated"):
        static_score += 20
        rationale.append("Binary appears packed or obfuscated")

    if behavior_flow:
        static_score += 15
        rationale.append("Clear execution behavior flow detected")

    # ------------------------------------------------
    # Dynamic Behavioral Scoring (if available)
    # ------------------------------------------------

    dynamic_score = 0

    if dynamic_findings:
        dynamic_score = calculate_behavioral_risk(dynamic_findings)

        if dynamic_findings.get("network", 0) > 0:
            rationale.append("Runtime outbound network activity observed")

        if dynamic_findings.get("process_injection", 0) > 0:
            rationale.append("Runtime process manipulation observed")

        if dynamic_findings.get("privilege", 0) > 0:
            rationale.append("Runtime privilege escalation attempt")

    # ------------------------------------------------
    # Hybrid Risk Fusion
    # ------------------------------------------------

    if dynamic_findings:
        # 60% static + 40% dynamic weighting
        final_score = round((static_score * 0.6) + (dynamic_score * 0.4))
        risk_model = "hybrid_static_dynamic_v1"
    else:
        final_score = static_score
        risk_model = "static_only_v1"

    # ------------------------------------------------
    # Verdict Logic
    # ------------------------------------------------

    verdict = (
        "high_risk_malware" if final_score >= 70 else
        "suspicious_artifact" if final_score >= 40 else
        "low_confidence_threat"
    )

    severity = classify_severity(final_score)

    return {
        "score": final_score,
        "severity": severity,
        "verdict": verdict,
        "rationale": rationale,
        "risk_model": risk_model,
        "static_component": static_score,
        "dynamic_component": dynamic_score
    }
