def score_risk(intents, obfuscation, behavior_flow):
    score = 0
    rationale = []

    purposes = set()
    for i in intents:
        purposes.update(i["purposes"])

    if "network_communication" in purposes:
        score += 30
        rationale.append("Active network communication detected")

    if "persistence" in purposes:
        score += 25
        rationale.append("Persistence mechanisms identified")

    if "credential_access" in purposes:
        score += 30
        rationale.append("Credential access behavior")

    if obfuscation["packed_or_obfuscated"]:
        score += 20
        rationale.append("Binary appears packed or obfuscated")

    if behavior_flow:
        score += 15
        rationale.append("Clear execution behavior flow detected")

    verdict = (
        "high_risk_malware" if score >= 70 else
        "suspicious_artifact" if score >= 40 else
        "low_confidence_threat"
    )

    return {
        "score": score,
        "verdict": verdict,
        "rationale": rationale
    }
