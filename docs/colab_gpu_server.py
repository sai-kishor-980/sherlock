"""
Sherlock AI — Google Colab GPU Inference Server
Paste this script into Google Colab (with T4 GPU enabled) or run the cells in SherlockAI_Colab_Inference_Bridge.ipynb.
"""

# Cell 1: Dependencies
# !pip install -q torch transformers peft bitsandbytes accelerate fastapi uvicorn pydantic

import os
import json
import time
import subprocess
import threading
import re
from typing import Any, Dict, Optional
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

# -------------------------------------------------------------
# 1. Model Initialization (Qwen2.5-7B in 4-bit NF4)
# -------------------------------------------------------------
BASE_MODEL_ID = "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"
print(f"[*] Loading Tokenizer for {BASE_MODEL_ID}...")
tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, trust_remote_code=True)

print(f"[*] Loading 4-bit Quantized Base Model onto GPU...")
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True
)

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_ID,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True
)
model.eval()
print("[+] Model loaded successfully on GPU!")

# -------------------------------------------------------------
# 2. FastAPI Inference Application
# -------------------------------------------------------------
app = FastAPI(title="Sherlock AI GPU Inference Bridge")

class InferenceRequest(BaseModel):
    domain: str
    evidence_type: str
    evidence: Any

@app.get("/")
def root():
    cuda_ok = torch.cuda.is_available()
    device_name = torch.cuda.get_device_name(0) if cuda_ok else "CPU"
    return {
        "status": "ONLINE",
        "service": "Sherlock AI Colab GPU Inference Bridge",
        "model": BASE_MODEL_ID,
        "cuda_available": cuda_ok,
        "device": device_name
    }

@app.post("/api/v1/inference")
def run_inference(req: InferenceRequest):
    try:
        # Domain Agent cognitive prompt
        system_prompt = (
            f"You are the expert {req.domain.upper()} Forensic Domain Agent for Agentic Sherlock AI. "
            "Analyze the given digital forensic evidence thoroughly and return a valid JSON object with the following fields: "
            "\"classification\" (BENIGN, MALICIOUS, or SUSPICIOUS), "
            "\"risk_level\" (INFORMATIONAL, LOW, MEDIUM, HIGH, or CRITICAL), "
            "\"reasoning\" (detailed cognitive forensic breakdown explaining attack vectors or indicators), "
            "\"key_evidence\" (list of specific suspicious artifacts, IPs, commands, or registry keys found), "
            "\"recommended_actions\" (list of forensic containment or eradication steps)."
        )

        evidence_text = json.dumps(req.evidence, indent=2) if isinstance(req.evidence, (dict, list)) else str(req.evidence)
        if len(evidence_text) > 4000:
            evidence_text = evidence_text[:4000] + "\n...[truncated for GPU context window]..."

        user_content = f"Domain: {req.domain}\nEvidence Type: {req.evidence_type}\n\nEvidence Content:\n{evidence_text}"

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

        prompt_str = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt_str, return_tensors="pt").to(model.device)

        with torch.inference_mode():
            outputs = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.2,
                top_p=0.9,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id
            )

        new_tokens = outputs[0][inputs.input_ids.shape[1]:]
        response_text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

        # Parse JSON from model generation
        parsed_json = None
        if "```json" in response_text:
            try:
                block = response_text.split("```json")[1].split("```")[0].strip()
                parsed_json = json.loads(block)
            except Exception:
                pass
        elif "{" in response_text and "}" in response_text:
            try:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                parsed_json = json.loads(response_text[start:end])
            except Exception:
                pass

        if not parsed_json or not isinstance(parsed_json, dict):
            # Safe structured wrapper if model generated free text
            low_text = response_text.lower()
            is_mal = any(w in low_text for w in ["malicious", "beacon", "c2", "attack", "injection", "privilege"])
            parsed_json = {
                "classification": "MALICIOUS" if is_mal else ("SUSPICIOUS" if "warning" in low_text else "BENIGN"),
                "risk_level": "HIGH" if is_mal else "MEDIUM",
                "reasoning": response_text,
                "key_evidence": [req.evidence_type],
                "recommended_actions": ["Isolate affected endpoint", "Inspect correlating network and memory artifacts"]
            }

        parsed_json["inference_provider"] = "Google Colab Remote GPU (Qwen2.5-7B LoRA)"
        parsed_json["domain"] = req.domain
        parsed_json["evidence_type"] = req.evidence_type
        return parsed_json

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# -------------------------------------------------------------
# 3. Tunnel and Server Runner
# -------------------------------------------------------------
def start_bridge():
    # Install cloudflared if not present
    subprocess.run(["wget", "-q", "-nc", "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"], check=False)
    subprocess.run(["dpkg", "-i", "cloudflared-linux-amd64.deb"], check=False)

    server_thread = threading.Thread(
        target=lambda: uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning"),
        daemon=True
    )
    server_thread.start()
    time.sleep(3)

    print("[*] Starting Cloudflare tunnel...")
    tunnel_proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", "http://127.0.0.1:8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in tunnel_proc.stderr:
        match = re.search(r"https://[-a-zA-Z0-9]+\.trycloudflare\.com", line)
        if match:
            url = match.group(0)
            print("=" * 68)
            print(f"[+] COLAB GPU INFERENCE TUNNEL ACTIVE: {url}")
            print(f"Paste this URL into your backend/.env:")
            print(f'COLAB_GPU_INFERENCE_URL={url}')
            print("=" * 68)
            break

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        tunnel_proc.terminate()

if __name__ == "__main__":
    start_bridge()
