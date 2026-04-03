from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoTokenizer, ModernBertForSequenceClassification
import torch
import os
import traceback

app = FastAPI(title="Zero-Day Agent API - ModernBERT Classifier")

class CVERequest(BaseModel):
    cve_description: str

# Global variables for the ML model
tokenizer = None
model = None
device = None

@app.on_event("startup")
async def load_model():
    """Initializes the ModernBERT engine on container startup."""
    global tokenizer, model, device
    model_path = "/app/model"
    
    try:
        print(f"[*] Starting engine. Path: {model_path}")
        
        tokenizer = AutoTokenizer.from_pretrained(
            model_path, 
            local_files_only=True, 
            trust_remote_code=True
        )
        
        model = ModernBertForSequenceClassification.from_pretrained(
            model_path, 
            local_files_only=True, 
            trust_remote_code=True
        )
        
        # Hardware acceleration
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        model.to(device)
        model.eval()
        
        print(f"--- SUCCESS ---")
        print(f"[+] ModernBERT Threat Intel Engine is LIVE on {str(device).upper()}")
        print(f"----------------")
        
    except Exception as e:
        print(f"--- LOAD ERROR ---")
        print(f"Details: {str(e)}")
        print(traceback.format_exc())
        print("------------------")

@app.post("/analyze")
async def analyze_vulnerability(request: CVERequest):
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model is not ready.")

    try:
        # 1. Prepare Input (Max context 512 for speed, model supports up to 8192)
        inputs = tokenizer(
            request.cve_description, 
            return_tensors="pt", 
            truncation=True, 
            max_length=512
        ).to(device)

        # 2. Run Inference
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1).squeeze().tolist()
            predicted_id = int(torch.argmax(logits, dim=1).item())

        # 3. MAPPING: 13-Class Vulnerability Labels from config.json
        labels = {
            0: "SQL Injection (SQLI)",
            1: "Cross-Site Scripting (XSS)",
            2: "Remote Code Execution (RCE)",
            3: "Buffer Overflow (B_OVERFLOW)",
            4: "Denial of Service (DOS)",
            5: "Server-Side Request Forgery (SSRF)",
            6: "Path Traversal",
            7: "Privilege Escalation (PRIV_ESC)",
            8: "Authentication Failure",
            9: "Information Disclosure",
            10: "Cross-Site Request Forgery (CSRF)",
            11: "Command Injection",
            12: "Other/General"
        }

        # 4. LOGIC: Map Vulnerability Type to Risk Level
        severity_map = {
            "Remote Code Execution (RCE)": "CRITICAL",
            "Command Injection": "CRITICAL",
            "Buffer Overflow (B_OVERFLOW)": "CRITICAL",
            "SQL Injection (SQLI)": "HIGH",
            "Privilege Escalation (PRIV_ESC)": "HIGH",
            "SSRF": "HIGH",
            "XSS": "MEDIUM",
            "Path Traversal": "MEDIUM",
            "Authentication Failure": "MEDIUM",
            "DOS": "MEDIUM",
            "CSRF": "LOW",
            "Information Disclosure": "LOW",
            "Other/General": "INFORMATIONAL"
        }

        # Safe lookup for the predicted type
        prediction_type = labels.get(predicted_id, f"Unclassified (ID: {predicted_id})")
        risk_level = severity_map.get(prediction_type, "UNKNOWN")
        
        # 5. Build full probability distribution for the UI
        scores = {}
        for i, p in enumerate(probabilities):
            name = labels.get(i, f"Class_{i}")
            scores[name] = f"{round(p * 100, 2)}%"

        return {
            "status": "success",
            "prediction": prediction_type, # This will show the Attack Type
            "risk_level": risk_level,      # This will show the Severity
            "confidence": f"{round(probabilities[predicted_id] * 100, 2)}%",
            "scores": scores
        }

    except Exception as e:
        print(f"[!] Inference Error: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/health")
def health():
    return {
        "status": "ready" if model else "loading", 
        "device": str(device),
        "classes": 13
    }