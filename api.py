import os
import json
import logging
from flask import Flask, request, jsonify, send_file
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from typing import List, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FTI Backend API")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FEATURES_DIR = "/app/data/features"
if not os.path.exists(FEATURES_DIR):
    # Fallback for local development outside docker
    FEATURES_DIR = os.path.join(os.path.dirname(__file__), "data/features")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = None
if GEMINI_API_KEY:
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("GenAI Client initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize GenAI Client: {e}")

# --- MODELS ---

class AnalysisRequest(BaseModel):
    filename: str

# --- UTILS ---

def get_sample_path(sample_id: str):
    path = os.path.join(FEATURES_DIR, sample_id)
    if not os.path.exists(path) or not os.path.isdir(path):
        raise HTTPException(status_code=404, detail="Sample not found")
    return path

def load_json(file_path: str):
    if not os.path.exists(file_path):
        return None
    with open(file_path, "r") as f:
        return json.load(f)

# --- ENDPOINTS ---

@app.get("/samples")
async def list_samples():
    """List all available analysis feature folders."""
    try:
        samples = []
        if os.path.exists(FEATURES_DIR):
            for entry in os.listdir(FEATURES_DIR):
                full_path = os.path.join(FEATURES_DIR, entry)
                if os.path.isdir(full_path) and "__" in entry:
                    samples.append(entry)
        return samples
    except Exception as e:
        logger.error(f"Error listing samples: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/samples/{sample_id}/summary")
async def get_sample_summary(sample_id: str):
    """Get metadata and threat summary for a sample."""
    path = get_sample_path(sample_id)
    metadata = load_json(os.path.join(path, "metadata.json"))
    threat = load_json(os.path.join(path, "threat_summary.json"))
    return {"metadata": metadata, "threat": threat}

@app.get("/samples/{sample_id}/analysis/static/hash")
async def get_static_hash(sample_id: str):
    """Get MD5/SHA256 from metadata."""
    path = get_sample_path(sample_id)
    metadata = load_json(os.path.join(path, "metadata.json"))
    if not metadata:
        raise HTTPException(status_code=404, detail="Metadata not found")
    return {
        "MD5": metadata.get("md5"),
        "SHA1": metadata.get("sha1"),
        "SHA256": metadata.get("sha256"),
        "STATUS": "ANALYSIS COMPLETE"
    }

@app.get("/samples/{sample_id}/analysis/static/entropy")
async def get_static_entropy(sample_id: str):
    """Get entropy from metadata."""
    path = get_sample_path(sample_id)
    metadata = load_json(os.path.join(path, "metadata.json"))
    if not metadata:
        raise HTTPException(status_code=404, detail="Metadata not found")
    return {"entropy": metadata.get("entropy", "N/A")}

@app.get("/samples/{sample_id}/analysis/static/pe")
async def get_static_pe(sample_id: str):
    """Get file type and threat summary."""
    path = get_sample_path(sample_id)
    metadata = load_json(os.path.join(path, "metadata.json"))
    threat = load_json(os.path.join(path, "threat_summary.json"))
    if not metadata:
        raise HTTPException(status_code=404, detail="Metadata not found")
    
    return {
        "file_type": metadata.get("architecture", "UNKNOWN"),
        "threat_summary": threat if threat else "NO THREAT SUMMARY AVAILABLE"
    }

@app.get("/samples/{sample_id}/analysis/static/functions")
async def get_static_functions(sample_id: str):
    """Get contents of functions.json."""
    path = get_sample_path(sample_id)
    functions_data = load_json(os.path.join(path, "functions.json"))
    if not functions_data:
        raise HTTPException(status_code=404, detail="Functions data not found")
    return functions_data

@app.get("/samples/{sample_id}/analysis/static/strings")
async def get_static_strings(sample_id: str):
    """Old strings endpoint, keeping for compatibility if needed."""
    path = get_sample_path(sample_id)
    functions_data = load_json(os.path.join(path, "functions.json"))
    if not functions_data:
        raise HTTPException(status_code=404, detail="Functions data not found")
    
    results = []
    for func in functions_data.get("functions", [])[:10]:
        name = func.get("function")
        behaviors = ", ".join(func.get("behaviors", []))
        results.append(f"FOUND: {name} ({behaviors})")
    
    return results if results else ["NO SIGNIFICANT STRINGS IDENTIFIED"]

@app.get("/samples/{sample_id}/analysis/dynamic")
async def get_dynamic_analysis(sample_id: str, network_only: bool = False):
    """Get analysis.json (data_targets) and dynamic_analysis.json."""
    path = get_sample_path(sample_id)
    analysis = load_json(os.path.join(path, "analysis.json"))
    dynamic = load_json(os.path.join(path, "dynamic_analysis.json"))
    
    results = []
    if analysis and "data_targets" in analysis:
        dt = analysis["data_targets"]
        if dt.get("urls"): results.append(f"NETWORK: {dt['urls']}")
        if not network_only:
            if dt.get("files"): results.append(f"FILES: {dt['files']}")
            if dt.get("registry_keys"): results.append(f"REGISTRY: {dt['registry_keys']}")
    
    if not network_only and dynamic:
        findings = dynamic.get("syscall_findings", {})
        for cat, count in findings.items():
            if count > 0:
                results.append(f"SYSCALL {cat.upper()}: {count} OBSERVED")
    
    return results if results else ["NO DYNAMIC BEHAVIOR OBSERVED"]

@app.post("/samples/{sample_id}/report")
async def generate_report(sample_id: str):
    """Generate a Gemini report from analysis.json."""
    if not client:
        return {"report": "GEMINI_API_KEY NOT CONFIGURED OR CLIENT FAILED TO INITIALIZE. AI ANALYSIS UNAVAILABLE."}
    
    path = get_sample_path(sample_id)
    analysis = load_json(os.path.join(path, "analysis.json"))
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis data not found")

    # Aggressive pruning for Gemini (minimal token usage)
    pruned_data = {
        "metadata": {
            "name": analysis.get("file_metadata", {}).get("binary_name"),
            "size": analysis.get("file_metadata", {}).get("size_bytes"),
            "entropy": analysis.get("file_metadata", {}).get("entropy")
        },
        "targets": {
            "urls": analysis.get("data_targets", {}).get("urls", [])[:3],
            "files": analysis.get("data_targets", {}).get("files", [])[:3],
            "keys": analysis.get("data_targets", {}).get("registry_keys", [])[:3]
        },
        "verdict": load_json(os.path.join(path, "threat_summary.json")).get("verdict")
    }

    try:
        prompt = f"Analyze malware data. Summarize threat level and key indicators (URLs/Keys). Be extremely concise.\nDATA: {json.dumps(pruned_data)}"
        
        response = client.models.generate_content(
            model="gemini-3-flash-preview",
            contents=prompt,
            
        )
        report_text = response.text
        
        # Save report for download
        report_path = os.path.join(path, "gemini_report.txt")
        with open(report_path, "w") as f:
            f.write(report_text)
            
        return {"report": report_text}
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return {"report": f"ERROR GENERATING AI REPORT: {str(e)}"}

@app.get("/samples/{sample_id}/download-report")
async def download_report(sample_id: str):
    """Download the generated Gemini report."""
    path = get_sample_path(sample_id)
    report_path = os.path.join(path, "gemini_report.txt")
    
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not generated yet")
    
    return FileResponse(path=report_path, filename=f"report_{sample_id}.txt", media_type='text/plain')

# --- FEDERATED LEARNING ENDPOINTS ---

@app.post("/federated/train")
async def trigger_federated_train():
    """Trigger a local federated learning round."""
    try:
        from federated.client import run_federated_round
        run_federated_round()
        return {"status": "Federated training round completed successfully"}
    except Exception as e:
        logger.error(f"Federated training error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/federated/status")
async def get_federated_status():
    """Check if a federated model is available locally."""
    try:
        from federated.local_model import FederatedRiskScorer
        scorer = FederatedRiskScorer()
        return {
            "model_available": scorer.is_available(),
            "model_type": "FederatedRiskScorer (Linear/SGD)"
        }
    except Exception as e:
        return {"model_available": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
