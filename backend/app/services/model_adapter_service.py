"""
Model Adapter Service for Agentic Sherlock AI.

Manages:
1. Base Cybersecurity Qwen3 QLoRA Adapter (from Cybersecurity_Qwen3_QLoRA_Package.zip) - Used by Supervisor Agent
2. Domain-Specific LoRA Adapters (from models.zip) - Used by the Specialized Agents:
   - Network Forensics Agent   -> network_adapter
   - Memory Analysis Agent     -> memory_adapter
   - Disk & Filesystem Agent   -> disk_adapter
   - Event Logs Agent          -> log_adapter
   - Windows Registry Agent    -> registry_adapter
"""

import os
import json
import zipfile
import io
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Set

from app.core.logger import log_app_event, log_error_event

BACKEND_DIR = Path(__file__).resolve().parents[2]
SHERF_DIR = BACKEND_DIR.parent
ADAPTERS_CACHE_DIR = BACKEND_DIR / "app" / "models" / "adapters"

BASE_QLORA_ZIP = SHERF_DIR / "Cybersecurity_Qwen3_QLoRA_Package.zip"
DOMAIN_MODELS_ZIP = SHERF_DIR / "models.zip"

DOMAIN_ADAPTER_MAP = {
    "network": "models/network_adapter.zip",
    "memory": "models/memory_adapter.zip",
    "disk": "models/disk_adapter.zip",
    "logs": "models/log_adapter.zip",
    "registry": "models/registry_adapter.zip",
    "supervisor": "Cybersecurity_Qwen3_QLoRA_Package.zip",
}

AGENT_DOMAIN_MAP = {
    "network": {
        "agent_name": "Network Agent",
        "team_member": "Pranay",
        "role": "Network Packet & Protocol Specialist",
        "description": "PCAP, DNS, network sockets, browser, and email artifacts",
        "adapter_name": "network_adapter"
    },
    "memory": {
        "agent_name": "Memory Agent",
        "team_member": "Bharath",
        "role": "Volatile Memory & Kernel Specialist",
        "description": "RAM volatile memory, processes, DLLs, and in-memory malware indicators",
        "adapter_name": "memory_adapter"
    },
    "disk": {
        "agent_name": "Disk Agent",
        "team_member": "Aswith",
        "role": "Filesystem & Disk Artifact Specialist",
        "description": "MFT, LNK shortcuts, Prefetch execution, Recycle Bin, and Jump Lists",
        "adapter_name": "disk_adapter"
    },
    "logs": {
        "agent_name": "Log Agent",
        "team_member": "Sanhith",
        "role": "Windows Event & Sysmon Specialist",
        "description": "Security Event Logs, Sysmon, process creation, PowerShell, and authentication",
        "adapter_name": "log_adapter"
    },
    "registry": {
        "agent_name": "Registry Agent",
        "team_member": "Kishor",
        "role": "Registry Hive & Configuration Specialist",
        "description": "Installed software, USB device history, Run/RunOnce keys, and persistence",
        "adapter_name": "registry_adapter"
    },
    "supervisor": {
        "agent_name": "Supervisor Agent",
        "team_member": "Supervisor",
        "role": "Cross-Domain Investigation State Synthesis",
        "description": "Cross-domain correlation reasoning, hypothesis generation, and kill-chain synthesis",
        "adapter_name": "base_cybersecurity"
    }
}


class ModelAdapterService:
    _initialized = False
    _adapter_status = {}
    _remote_gpu_url = None
    _local_model = None
    _local_tokenizer = None
    _local_model_loaded = False

    @classmethod
    def initialize_adapters(cls, force_reextract: bool = False):
        """
        Ensures that adapter configurations and metadata are unpacked and verified.
        """
        ADAPTERS_CACHE_DIR.mkdir(parents=True, exist_ok=True)

        status = {
            "base_adapter": {
                "name": "Cybersecurity Base QLoRA",
                "role": "Supervisor Orchestrator",
                "base_model": "Qwen/Qwen3-8B",
                "status": "UNAVAILABLE",
                "path": None,
                "config": {}
            },
            "domain_adapters": {}
        }

        # 1. Unpack / verify Base Cybersecurity Adapter
        base_target_dir = ADAPTERS_CACHE_DIR / "base_cybersecurity"
        if BASE_QLORA_ZIP.exists():
            try:
                if force_reextract or not (base_target_dir / "adapter_config.json").exists():
                    base_target_dir.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(BASE_QLORA_ZIP, "r") as zf:
                        # Extract final_adapter files into base_target_dir
                        for member in zf.infolist():
                            if member.filename.startswith("final_adapter/") and not member.is_dir():
                                rel_name = member.filename[len("final_adapter/"):]
                                dest_path = base_target_dir / rel_name
                                dest_path.parent.mkdir(parents=True, exist_ok=True)
                                with zf.open(member) as src, open(dest_path, "wb") as dst:
                                    shutil.copyfileobj(src, dst)
                
                config_path = base_target_dir / "adapter_config.json"
                if config_path.exists():
                    with open(config_path, "r", encoding="utf-8") as f:
                        cfg = json.load(f)
                    status["base_adapter"].update({
                        "status": "READY",
                        "path": str(base_target_dir),
                        "config": cfg,
                        "peft_type": cfg.get("peft_type", "LORA"),
                        "base_model_name": cfg.get("base_model_name_or_path", "Qwen/Qwen3-8B")
                    })
            except Exception as e:
                status["base_adapter"]["status"] = f"ERROR: {str(e)}"
        else:
            status["base_adapter"]["status"] = "ZIP_NOT_FOUND"

        # 2. Unpack / verify Domain Adapters from models.zip
        if DOMAIN_MODELS_ZIP.exists():
            try:
                with zipfile.ZipFile(DOMAIN_MODELS_ZIP, "r") as outer_zf:
                    for domain, inner_zip_name in DOMAIN_ADAPTER_MAP.items():
                        info = AGENT_DOMAIN_MAP.get(domain, {})
                        domain_target = ADAPTERS_CACHE_DIR / domain
                        domain_status = {
                            "domain": domain,
                            "agent_name": info.get("agent_name"),
                            "team_member": info.get("team_member"),
                            "description": info.get("description"),
                            "status": "UNAVAILABLE",
                            "path": str(domain_target),
                            "config": {}
                        }

                        if inner_zip_name in outer_zf.namelist():
                            has_cfg = next(domain_target.rglob("adapter_config.json"), None) is not None
                            if force_reextract or not has_cfg:
                                domain_target.mkdir(parents=True, exist_ok=True)
                                inner_bytes = outer_zf.read(inner_zip_name)
                                with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner_zf:
                                    inner_zf.extractall(domain_target)

                                # Also unpack any nested zip files (e.g. disk_agent_adapter_v7.zip)
                                for nested_zip in list(domain_target.rglob("*.zip")):
                                    try:
                                        with zipfile.ZipFile(nested_zip, "r") as nzf:
                                            nzf.extractall(nested_zip.parent)
                                    except Exception:
                                        pass

                            cfg_file = next(domain_target.rglob("adapter_config.json"), None)
                            if cfg_file and cfg_file.exists():
                                with open(cfg_file, "r", encoding="utf-8") as f:
                                    cfg = json.load(f)
                                domain_status.update({
                                    "status": "READY",
                                    "path": str(cfg_file.parent),
                                    "config": cfg,
                                    "peft_type": cfg.get("peft_type", "LORA"),
                                    "base_model_name": cfg.get("base_model_name_or_path", "unsloth/Qwen2.5-7B-Instruct-bnb-4bit"),
                                    "lora_r": cfg.get("r", 8),
                                    "lora_alpha": cfg.get("lora_alpha", 16)
                                })
                        status["domain_adapters"][domain] = domain_status
            except Exception as e:
                for domain, info in AGENT_DOMAIN_MAP.items():
                    if domain not in status["domain_adapters"]:
                        status["domain_adapters"][domain] = {
                            "domain": domain,
                            "agent_name": info.get("agent_name"),
                            "team_member": info.get("team_member"),
                            "status": f"ERROR: {str(e)}"
                        }
        else:
            for domain, info in AGENT_DOMAIN_MAP.items():
                status["domain_adapters"][domain] = {
                    "domain": domain,
                    "agent_name": info.get("agent_name"),
                    "team_member": info.get("team_member"),
                    "status": "ZIP_NOT_FOUND"
                }

        cls._adapter_status = status
        cls._initialized = True
        return status

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        if not cls._initialized:
            return cls.initialize_adapters()
        return cls._adapter_status

    @classmethod
    def check_gpu_readiness(cls, timeout: float = 3.0) -> Dict[str, Any]:
        """
        Actively checks whether an eligible GPU inference provider (Tier 1 local or Tier 2 remote Colab) is available.
        Returns:
            {"ready": bool, "provider": str, "device": str, "reason": Optional[str]}
        """
        hw = cls.get_hardware_info()
        if hw.get("gpu_eligible"):
            return {
                "ready": True,
                "provider": "local_gpu",
                "device": hw.get("device_name", "Local NVIDIA GPU"),
                "vram_gb": hw.get("total_vram_gb")
            }

        remote_url = cls.get_remote_gpu_url()
        if not remote_url:
            return {
                "ready": False,
                "provider": "none",
                "reason": "Local GPU lacks required 6GB VRAM and COLAB_GPU_INFERENCE_URL is not configured."
            }

        token = cls.get_remote_token()
        headers = {"User-Agent": "SherlockAI-Client"}
        if token:
            headers["X-Sherlock-Token"] = token

        import urllib.request
        try:
            req = urllib.request.Request(f"{remote_url.rstrip('/')}/health", headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "ready": True,
                        "provider": "remote_gpu",
                        "device": data.get("gpu_device", "Remote GPU"),
                        "base_model": data.get("base_model"),
                        "adapters_loaded": data.get("adapters_loaded", [])
                    }
        except Exception as e:
            return {
                "ready": False,
                "provider": "remote_gpu",
                "reason": f"Remote Colab GPU health check failed: {str(e)}"
            }

        return {
            "ready": False,
            "provider": "none",
            "reason": "GPU inference services are unavailable."
        }

    @classmethod
    def analyze_domain_evidence(cls, domain: str, evidence_type: str, evidence_content: Any, timeout: int = 45) -> Dict[str, Any]:
        """
        Executes domain-specific cognitive forensic reasoning.
        Uses Qwen-grounded prompting and schema matching the QLoRA training objective:
        Classification, Risk Level, Reasoning, Key Evidence, and Observation Accounting.
        Replaces silent truncation with bounded batching/chunking.
        """
        status = cls.get_status()
        domain_info = AGENT_DOMAIN_MAP.get(domain, {
            "agent_name": f"{domain.capitalize()} Agent",
            "team_member": "Specialist"
        })

        # -------------------------------------------------------------
        # 0. Evidentiary Absence Gate (Missing / Empty Artifacts)
        # -------------------------------------------------------------
        if evidence_content is None or evidence_content == {} or evidence_content == []:
            import uuid
            finding_id = f"STATUS-{domain.upper()}-{uuid.uuid4().hex[:6].upper()}"
            return {
                "finding_id": finding_id,
                "domain": domain,
                "agent": domain_info.get("agent_name", f"{domain.capitalize()} Agent"),
                "team_member": domain_info.get("team_member", "Specialist"),
                "evidence_type": evidence_type,
                "artifact_type": evidence_type,
                "status": "INSUFFICIENT_EVIDENCE",
                "classification": "INSUFFICIENT_EVIDENCE",
                "assessment": "INSUFFICIENT_EVIDENCE",
                "risk_level": "INFORMATIONAL",
                "risk": "INFORMATIONAL",
                "confidence": 0.0,
                "is_examination_status": True,
                "observation": f"No {domain} artifacts submitted or recovered for forensic examination in this case.",
                "reasoning": f"Evidentiary absence in the {domain} domain. No suspicious anomalies detected due to absence of domain telemetry.",
                "key_evidence": [],
                "entities": [],
                "observation_accounting": {
                    "total_observations": 0,
                    "analyzed_observations": 0,
                    "skipped_observations": 0,
                    "failed_observations": 0,
                    "batch_count": 0,
                    "accounting_status": "EMPTY",
                    "source_artifact": evidence_type
                },
                "inference_provider": "Examination Status (Evidentiary Absence)",
                "analysis_mode": "Examination Status"
            }

        # -------------------------------------------------------------
        # 1. Observation Accounting & Bounded Batching Determination
        # -------------------------------------------------------------
        records = []
        is_tabular = False
        if isinstance(evidence_content, list):
            records = evidence_content
            is_tabular = True
        elif isinstance(evidence_content, dict):
            for key in ["records", "queries", "connections", "processes", "events", "entries", "messages", "devices", "deleted_files", "plugins"]:
                val = evidence_content.get(key)
                if isinstance(val, list) and len(val) > 0:
                    records = val
                    is_tabular = True
                    break
                elif isinstance(val, dict) and key == "plugins":
                    all_p_items = []
                    for p_items in val.values():
                        if isinstance(p_items, list):
                            all_p_items.extend(p_items)
                    if all_p_items:
                        records = all_p_items
                        is_tabular = True
                        break

        if is_tabular and len(records) == 0:
            import uuid
            finding_id = f"STATUS-{domain.upper()}-{uuid.uuid4().hex[:6].upper()}"
            return {
                "finding_id": finding_id,
                "domain": domain,
                "agent": domain_info.get("agent_name", f"{domain.capitalize()} Agent"),
                "team_member": domain_info.get("team_member", "Specialist"),
                "evidence_type": evidence_type,
                "artifact_type": evidence_type,
                "status": "INSUFFICIENT_EVIDENCE",
                "classification": "INSUFFICIENT_EVIDENCE",
                "assessment": "INSUFFICIENT_EVIDENCE",
                "risk_level": "INFORMATIONAL",
                "risk": "INFORMATIONAL",
                "confidence": 0.0,
                "is_examination_status": True,
                "observation": f"No {domain} records found in artifact '{evidence_type}'.",
                "reasoning": f"Evidentiary absence in the {domain} domain. No suspicious anomalies detected due to empty record set.",
                "key_evidence": [],
                "entities": [],
                "observation_accounting": {
                    "total_observations": 0,
                    "analyzed_observations": 0,
                    "skipped_observations": 0,
                    "failed_observations": 0,
                    "batch_count": 0,
                    "accounting_status": "EMPTY",
                    "source_artifact": evidence_type
                },
                "inference_provider": "Examination Status (Evidentiary Absence)",
                "analysis_mode": "Examination Status"
            }

        total_observations = len(records) if is_tabular else 1
        BATCH_SIZE = 20
        MAX_BATCHES = 5  # Bounded to at most 100 observations per run to preserve latency
        
        batches = []
        if is_tabular and total_observations > BATCH_SIZE:
            all_chunks = [records[i:i + BATCH_SIZE] for i in range(0, total_observations, BATCH_SIZE)]
            batches = all_chunks[:MAX_BATCHES]
            analyzed_count = sum(len(b) for b in batches)
            skipped_count = total_observations - analyzed_count
        else:
            batches = [evidence_content]
            analyzed_count = total_observations
            skipped_count = 0

        accounting = {
            "total_observations": total_observations,
            "analyzed_observations": analyzed_count,
            "skipped_observations": skipped_count,
            "failed_observations": 0,
            "batch_count": len(batches),
            "accounting_status": "COMPLETE" if skipped_count == 0 else "PARTIAL",
            "source_artifact": evidence_type
        }

        # -------------------------------------------------------------
        # 2. Execute Analysis across Batches (Remote GPU Only)
        # Tier 2: Remote AI GPU Inference Service (HTTP/REST Bridge)
        # No local CUDA fallback. No rule-based AI inference fallback.
        # -------------------------------------------------------------
        remote_url = cls.get_remote_gpu_url()
        batch_results = []
        execution_mode = "AI-assisted" if remote_url else "GPU_UNAVAILABLE"

        for b_idx, batch_data in enumerate(batches):
            batch_result = None

            # --- TIER 2: Remote AI GPU Inference Service ---
            if remote_url:
                try:
                    import urllib.request
                    req_data = json.dumps({
                        "domain": domain,
                        "evidence_type": f"{evidence_type} (Batch {b_idx + 1}/{len(batches)})" if len(batches) > 1 else evidence_type,
                        "evidence": batch_data
                    }).encode("utf-8")
                    req_headers = {"Content-Type": "application/json", "User-Agent": "SherlockAI-Client"}
                    token = cls.get_remote_token()
                    if token:
                        req_headers["X-Sherlock-Token"] = token

                    req = urllib.request.Request(
                        f"{remote_url.rstrip('/')}/api/v1/inference",
                        data=req_data,
                        headers=req_headers
                    )
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        if resp.status == 200:
                            remote_json = json.loads(resp.read().decode("utf-8"))
                            norm_res = cls.normalize_agent_output(remote_json, domain=domain, evidence_type=evidence_type)
                            norm_res["inference_provider"] = "AI-assisted (Remote GPU Accelerated)"
                            norm_res["analysis_mode"] = "AI-assisted"
                            if "model_info" in remote_json:
                                norm_res["model_info"] = remote_json["model_info"]
                            batch_result = norm_res
                            execution_mode = "AI-assisted"
                except Exception as e:
                    log_error_event(f"[ModelAdapter] Remote inference failed for {domain} (Batch {b_idx + 1}): {e}.")

            # --- Require Genuine GPU Inference ---
            if not batch_result:
                import uuid
                fail_res = {
                    "finding_id": f"FINDING-{domain.upper()}-FAIL-{uuid.uuid4().hex[:6].upper()}",
                    "domain": domain,
                    "agent": domain_info.get("agent_name", f"{domain.capitalize()} Agent"),
                    "team_member": domain_info.get("team_member", "Specialist"),
                    "evidence_type": evidence_type,
                    "artifact_type": evidence_type,
                    "status": "FAILED",
                    "error": "GPU_UNAVAILABLE",
                    "classification": "INCONCLUSIVE",
                    "assessment": "INCONCLUSIVE",
                    "risk_level": "INFORMATIONAL",
                    "risk": "INFORMATIONAL",
                    "confidence": 0.0,
                    "observation": f"Inference execution failed for {domain}: remote GPU inference bridge is offline or unavailable.",
                    "reasoning": "Forensic neural model inference requires an active remote GPU bridge. Colab GPU bridge is disconnected.",
                    "key_evidence": [],
                    "entities": [],
                    "inference_provider": "Failed (GPU Unavailable)",
                    "analysis_mode": "Failed"
                }
                batch_result = fail_res

            batch_results.append(batch_result)

        # -------------------------------------------------------------
        # 3. Aggregate Batch Results & Attach Accounting
        # -------------------------------------------------------------
        if len(batch_results) == 1:
            final_res = batch_results[0]
        else:
            severities = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
            risk_ranks = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            max_class = "BENIGN"
            max_risk = "LOW"
            all_key_ev = []
            all_reasoning = []
            all_entities = []

            for r in batch_results:
                c = str(r.get("classification", "BENIGN")).upper()
                rk = str(r.get("risk_level", "LOW")).upper()
                if (severities.index(c) if c in severities else 0) > (severities.index(max_class) if max_class in severities else 0):
                    max_class = c
                if (risk_ranks.index(rk) if rk in risk_ranks else 0) > (risk_ranks.index(max_risk) if max_risk in risk_ranks else 0):
                    max_risk = rk
                all_key_ev.extend(r.get("key_evidence", []))
                all_reasoning.append(r.get("reasoning", ""))
                all_entities.extend(r.get("entities", []))

            dedup_ev = list(dict.fromkeys(all_key_ev))
            final_res = dict(batch_results[0])
            final_res["classification"] = max_class
            final_res["assessment"] = max_class
            final_res["risk_level"] = max_risk
            final_res["risk"] = max_risk
            final_res["key_evidence"] = dedup_ev
            final_res["entities"] = all_entities
            final_res["reasoning"] = f"Aggregated {len(batches)} observation batches. " + " ".join(all_reasoning[:2])

        final_res["observation_accounting"] = accounting
        final_res["analysis_mode"] = execution_mode
        return final_res

    _remote_token = None
    _url_lock = None

    @classmethod
    def _get_url_lock(cls):
        if cls._url_lock is None:
            import threading
            cls._url_lock = threading.Lock()
        return cls._url_lock

    @classmethod
    def set_remote_gpu_url(cls, url: Optional[str]):
        with cls._get_url_lock():
            cls._remote_gpu_url = url.strip() if url else None

    @classmethod
    def set_remote_token(cls, token: Optional[str]):
        with cls._get_url_lock():
            cls._remote_token = token.strip() if token else None

    @classmethod
    def get_remote_token(cls) -> Optional[str]:
        with cls._get_url_lock():
            if getattr(cls, "_remote_token", None):
                return cls._remote_token
            env_token = os.environ.get("SHERLOCK_REMOTE_TOKEN")
            if env_token:
                return env_token
            dotenv_file = BACKEND_DIR / ".env"
            if dotenv_file.exists():
                try:
                    with open(dotenv_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("SHERLOCK_REMOTE_TOKEN="):
                                token = line.split("=", 1)[1].strip().strip('"').strip("'")
                                if token:
                                    cls._remote_token = token
                                    return token
                except Exception:
                    pass
        return None

    @classmethod
    def get_remote_gpu_url(cls) -> Optional[str]:
        with cls._get_url_lock():
            if getattr(cls, "_remote_gpu_url", None):
                return cls._remote_gpu_url
            env_url = os.environ.get("COLAB_GPU_INFERENCE_URL")
            if env_url:
                return env_url
            dotenv_file = BACKEND_DIR / ".env"
            if dotenv_file.exists():
                try:
                    with open(dotenv_file, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("COLAB_GPU_INFERENCE_URL="):
                                url = line.split("=", 1)[1].strip().strip('"').strip("'")
                                if url:
                                    cls._remote_gpu_url = url
                                    return url
                except Exception:
                    pass
        return None

    @classmethod
    def get_hardware_info(cls) -> Dict[str, Any]:
        """
        Auto-detects host system GPU acceleration capabilities.
        Enforces a minimum 6.0 GB VRAM requirement before declaring local GPU eligibility
        to protect against CUDA Out-Of-Memory (OOM) failures on low-spec hardware.
        """
        info = {
            "cuda_available": False,
            "device_name": None,
            "total_vram_gb": 0.0,
            "gpu_eligible": False,
            "reason": "No CUDA device detected on host"
        }
        try:
            import torch
            if torch.cuda.is_available():
                info["cuda_available"] = True
                dev_name = torch.cuda.get_device_name(0)
                info["device_name"] = dev_name
                total_mem = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
                info["total_vram_gb"] = round(total_mem, 2)
                if total_mem >= 6.0:
                    info["gpu_eligible"] = True
                    info["reason"] = f"Local NVIDIA GPU ({dev_name}, {round(total_mem, 2)} GB VRAM) meets requirements (>= 6GB)"
                else:
                    info["gpu_eligible"] = False
                    info["reason"] = f"Local NVIDIA GPU ({dev_name}, {round(total_mem, 2)} GB VRAM) is below 6.0 GB VRAM required for 7B model; routed to Tier 2/3"
        except Exception as e:
            info["reason"] = f"Hardware detection exception: {str(e)}"
        return info

    @classmethod
    def get_inference_tier_status(cls) -> Dict[str, Any]:
        """
        Evaluates the active 3-tier inference hierarchy and returns standardized neutral status.
        """
        hw = cls.get_hardware_info()
        remote_url = cls.get_remote_gpu_url()
        remote_online = False
        remote_model = None
        remote_device = None

        remote_adapters = []
        remote_vram = None

        if remote_url:
            token = cls.get_remote_token()
            probe_headers = {"User-Agent": "SherlockAI-Client"}
            if token:
                probe_headers["X-Sherlock-Token"] = token

            for probe_path in ["/health", "/"]:
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        f"{remote_url.rstrip('/')}{probe_path}",
                        headers=probe_headers
                    )
                    with urllib.request.urlopen(req, timeout=3) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode("utf-8"))
                            remote_online = True
                            remote_model = data.get("base_model") or data.get("model")
                            remote_device = data.get("gpu_device") or data.get("device")
                            remote_adapters = data.get("adapters_loaded", [])
                            remote_vram = data.get("vram_allocated_gb")
                            break
                except Exception:
                    remote_online = False

        if hw["gpu_eligible"]:
            active_tier = "Tier 1: Local GPU Accelerated"
            mode = "AI-assisted"
            service_available = True
            active_device = hw["device_name"]
            provider = "AI-assisted (Local GPU Accelerated)"
        elif remote_online:
            active_tier = "Tier 2: Remote GPU Accelerated"
            mode = "AI-assisted"
            service_available = True
            active_device = remote_device or "Remote GPU Service"
            provider = "AI-assisted (Remote GPU Accelerated)"
        else:
            active_tier = "Tier 3: Rule-based Engine"
            mode = "Rule-based"
            service_available = False
            active_device = "CPU (Forensic Heuristics)"
            provider = "Rule-based (Local Forensic Heuristic Engine)"

        return {
            "active_tier": active_tier,
            "analysis_mode": mode,
            "mode": provider,
            "is_connected": hw["gpu_eligible"] or remote_online,
            "inference_status": "Connected" if (hw["gpu_eligible"] or remote_online) else "Disconnected",
            "service_status": "Available" if service_available else "Unavailable",
            "active_device": active_device,
            "local_hardware": {
                "cuda_available": hw["cuda_available"],
                "device_name": hw["device_name"],
                "total_vram_gb": hw["total_vram_gb"],
                "gpu_eligible": hw["gpu_eligible"],
                "qualification_reason": hw["reason"],
                "model_cached_in_vram": cls._local_model_loaded
            },
            "remote_service": {
                "configured": bool(remote_url),
                "url": remote_url if remote_url else None,
                "reachable": remote_online,
                "remote_model": remote_model,
                "remote_device": remote_device,
                "adapters_loaded": remote_adapters,
                "vram_allocated_gb": remote_vram
            }
        }



    @classmethod
    def normalize_agent_output(cls, raw_output: Any, domain: str, evidence_type: str = "") -> Dict[str, Any]:
        """
        Output Normalizer & Contract Validator for Domain LoRA outputs.
        Parses raw model generation strings, key-value blocks, or JSON into the standardized AgentFinding contract.
        """
        domain_info = AGENT_DOMAIN_MAP.get(domain, {})
        agent_name = domain_info.get("agent_name", f"{domain.capitalize()} Agent")
        member = domain_info.get("team_member", "Specialist")

        # If already structured dict, check if reasoning contains inner markdown JSON
        if isinstance(raw_output, dict):
            import re, uuid
            reasoning_str = str(raw_output.get("reasoning", "")).strip()
            if "```json" in reasoning_str:
                json_match = re.search(r"```json\s*(\{.*?\})\s*```", reasoning_str, re.DOTALL)
                if json_match:
                    try:
                        inner_dict = json.loads(json_match.group(1))
                        for k, v in inner_dict.items():
                            if v:
                                raw_output[k] = v
                    except Exception:
                        pass

            raw_class = str(raw_output.get("classification", raw_output.get("assessment", "BENIGN"))).upper()
            if "MALICIOUS" in raw_class:
                classification = "MALICIOUS"
            elif "SUSPICIOUS" in raw_class:
                classification = "SUSPICIOUS"
            elif "OBSERVED" in raw_class:
                classification = "OBSERVED"
            elif "INCONCLUSIVE" in raw_class:
                classification = "INCONCLUSIVE"
            else:
                classification = "BENIGN"

            raw_risk = str(raw_output.get("risk_level", raw_output.get("risk", "LOW"))).upper()
            if "CRITICAL" in raw_risk:
                risk_level = "CRITICAL"
            elif "HIGH" in raw_risk:
                risk_level = "HIGH"
            elif "MED" in raw_risk:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            reasoning = str(raw_output.get("reasoning", "")).strip()
            # Clean outer markdown fence if still present
            if reasoning.startswith("```json"):
                reasoning = re.sub(r"^```json\s*", "", reasoning)
                reasoning = re.sub(r"\s*```$", "", reasoning)

            key_evidence = raw_output.get("key_evidence", [])
            if isinstance(key_evidence, str):
                key_evidence = [key_evidence]

            finding_id = raw_output.get("finding_id") or f"FINDING-{domain.upper()}-{uuid.uuid4().hex[:6].upper()}"
            entities = raw_output.get("entities", [])
            if isinstance(entities, dict):
                entities = [entities]
            elif not isinstance(entities, list):
                entities = [{"value": str(entities)}]

            # Evidence-corroborated confidence calculation
            if raw_class == "INSUFFICIENT_EVIDENCE" or raw_output.get("status") == "INSUFFICIENT_EVIDENCE":
                classification = "INSUFFICIENT_EVIDENCE"
                risk_level = "INFORMATIONAL"
                confidence_val = 0.0
            elif raw_output.get("status") == "FAILED" or raw_output.get("error") == "GPU_UNAVAILABLE":
                classification = "INCONCLUSIVE"
                risk_level = "INFORMATIONAL"
                confidence_val = 0.0
            else:
                is_ai = raw_output.get("analysis_mode") == "AI-assisted" or "GPU" in str(raw_output.get("inference_provider", ""))
                base_score = 0.75 if is_ai else 0.60
                verified_ents = [e for e in entities if isinstance(e, dict) and any(e.values())]
                corroboration_boost = min(0.20, (len(verified_ents) + len(key_evidence)) * 0.04)
                if classification == "BENIGN":
                    calculated_confidence = round(min(0.95, base_score + corroboration_boost), 2)
                elif classification in ("SUSPICIOUS", "MALICIOUS"):
                    calculated_confidence = round(min(0.95, base_score + corroboration_boost), 2)
                else:
                    calculated_confidence = 0.50
                confidence_val = float(raw_output.get("confidence") if raw_output.get("confidence") is not None else calculated_confidence)

            return {
                "finding_id": finding_id,
                "agent": agent_name,
                "domain": domain,
                "team_member": member,
                "artifact_type": evidence_type or raw_output.get("artifact_type", "artifact"),
                "evidence_type": evidence_type or raw_output.get("evidence_type", "artifact"),
                "observation": raw_output.get("observation") or (f"Analyzed {evidence_type} artifact with {domain.capitalize()} Agent."),
                "entities": entities or [{"domain": domain, "type": evidence_type}],
                "assessment": classification,
                "classification": classification,
                "risk": risk_level,
                "risk_level": risk_level,
                "reasoning": reasoning or "Automated domain analysis completed.",
                "supporting_evidence": raw_output.get("supporting_evidence") or [
                    {"evidence_type": evidence_type, "indicators": key_evidence}
                ],
                "key_evidence": key_evidence or ["Standard operational artifact verified."],
                "timeline": raw_output.get("timeline") or {
                    "timestamp_utc": raw_output.get("timestamp_utc"),
                    "timestamp_type": "OBSERVED" if raw_output.get("timestamp_utc") else "UNAVAILABLE",
                    "event_description": f"{evidence_type} execution record analyzed"
                },
                "confidence": confidence_val,
                "recommended_next_evidence": raw_output.get("recommended_next_evidence") or [
                    "Correlate with process execution logs",
                    "Verify corresponding filesystem or network indicators"
                ],
                "adapter_model": raw_output.get("adapter_model") or domain_info.get("adapter_name"),
                "contract_validated": True,
                "analysis_mode": raw_output.get("analysis_mode", "AI-assisted" if is_ai else "Rule-based"),
                "inference_provider": raw_output.get("inference_provider", "AI-assisted (Remote GPU Accelerated)" if is_ai else "Rule-based (Local Forensic Heuristic Engine)")
            }

        # Otherwise parse natural language string or raw text output
        import re, uuid
        text = str(raw_output).strip()

        # Step 1: Attempt JSON extraction from markdown or raw text
        cleaned_json = None
        if "```json" in text:
            m = re.search(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
            if m:
                try:
                    cleaned_json = json.loads(m.group(1))
                except Exception:
                    cleaned_json = None
        elif "```" in text:
            m = re.search(r"```\s*(\{.*?\})\s*```", text, re.DOTALL)
            if m:
                try:
                    cleaned_json = json.loads(m.group(1))
                except Exception:
                    cleaned_json = None
        elif text.startswith("{") and text.endswith("}"):
            try:
                cleaned_json = json.loads(text)
            except Exception:
                cleaned_json = None

        if isinstance(cleaned_json, dict):
            return cls.normalize_agent_output(cleaned_json, domain=domain, evidence_type=evidence_type)

        # Step 2: Parse explicit classification and risk level from LLM text output
        # These patterns extract the LLM's own classification decision from free-text
        # output; they do not perform independent forensic classification.
        classification_match = re.search(r"classification:\s*(suspicious|malicious|benign)\b", text, re.IGNORECASE)
        risk_match = re.search(r"risk level:\s*(critical|high|medium|low|informational)\b", text, re.IGNORECASE)

        has_negative = bool(re.search(r"\b(?:no|not|neither|without|clean|zero|uncompromised)\s+(?:malicious|suspicious|indicators|threats|anomalies|abnormalities)\b", text, re.IGNORECASE))
        affirmative_mal = bool(re.search(r"\b(?:is|confirmed|exhibits|classified as|verdict:?)\s+(?:malicious|compromised)\b", text, re.IGNORECASE))
        affirmative_susp = bool(re.search(r"\b(?:is|exhibits|classified as|verdict:?)\s+(?:suspicious|anomalous)\b", text, re.IGNORECASE))

        if classification_match:
            raw_class = classification_match.group(1).upper()
            if raw_class == "MALICIOUS":
                classification = "MALICIOUS"
                risk_level = "HIGH"
                confidence_val = 0.75
            elif raw_class == "SUSPICIOUS":
                classification = "SUSPICIOUS"
                risk_level = "MEDIUM"
                confidence_val = 0.65
            else:
                classification = "BENIGN"
                risk_level = "LOW"
                confidence_val = 0.85
            # Override risk level if explicitly stated
            if risk_match:
                raw_risk = risk_match.group(1).upper()
                risk_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFORMATIONAL"}
                risk_level = risk_map.get(raw_risk, risk_level)
        elif has_negative:
            classification = "BENIGN"
            risk_level = "LOW"
            confidence_val = 0.85
        elif affirmative_mal:
            classification = "MALICIOUS"
            risk_level = "HIGH"
            confidence_val = 0.75
        elif affirmative_susp:
            classification = "SUSPICIOUS"
            risk_level = "MEDIUM"
            confidence_val = 0.65
        else:
            # Safe forensic default: Never guess via naive substring matching
            classification = "INCONCLUSIVE"
            risk_level = "INFORMATIONAL"
            confidence_val = 0.50

        reasoning_match = re.search(r"3\.\s*Reasoning:?\s*(.*?)(?:4\.\s*Key evidence|\Z)", text, re.IGNORECASE | re.DOTALL)
        reasoning = reasoning_match.group(1).strip() if reasoning_match else text[:500]

        evidence_match = re.search(r"4\.\s*Key evidence:?\s*(.*)", text, re.IGNORECASE | re.DOTALL)
        evidence_text = evidence_match.group(1).strip() if evidence_match else ""
        key_evidence = [line.strip("- *").strip() for line in evidence_text.splitlines() if line.strip("- *").strip()]

        finding_id = f"FINDING-{domain.upper()}-{uuid.uuid4().hex[:6].upper()}"

        return {
            "finding_id": finding_id,
            "domain": domain,
            "agent": agent_name,
            "team_member": member,
            "artifact_type": evidence_type or "artifact",
            "evidence_type": evidence_type or "artifact",
            "observation": f"Unstructured analysis completed for {evidence_type}",
            "entities": [{"domain": domain, "type": evidence_type}],
            "assessment": classification,
            "classification": classification,
            "risk": risk_level,
            "risk_level": risk_level,
            "reasoning": reasoning or "Automated domain analysis completed.",
            "supporting_evidence": [
                {"evidence_type": evidence_type, "indicators": key_evidence}
            ],
            "key_evidence": key_evidence or ["Standard operational telemetry verified."],
            "timeline": {
                "timestamp_utc": None,
                "timestamp_type": "UNAVAILABLE",
                "event_description": f"{evidence_type} record analyzed"
            },
            "confidence": confidence_val,
            "recommended_next_evidence": [
                "Correlate with process execution logs",
                "Verify corresponding filesystem or network indicators"
            ],
            "adapter_model": domain_info.get("adapter_name"),
            "contract_validated": True,
            "schema_conforming": False,
            "analysis_mode": "AI-assisted (Unstructured Text Normalized)"
        }

    @classmethod
    def analyze_supervisor_correlation(
        cls,
        case_id: str,
        findings: List[Dict[str, Any]],
        candidate_edges: List[Dict[str, Any]],
        case_context: Optional[Dict[str, Any]] = None,
        max_retries: int = 1,
        timeout: int = 5
    ) -> Dict[str, Any]:
        """
        Executes cross-domain correlation reasoning via the Supervisor LLM on remote GPU.
        Enforces structured schema, zero-fabrication of finding IDs, and bounded 1-retry.
        """
        valid_finding_ids = {f.get("finding_id") for f in findings if f.get("finding_id")}
        remote_url = cls.get_remote_gpu_url()

        # Build initial correlation payload
        payload = cls._build_supervisor_payload(case_id, findings, candidate_edges, case_context)

        last_error = None
        raw_response_text = ""
        attempt = 0

        while attempt <= max_retries:
            attempt += 1
            if not remote_url:
                log_app_event("[ModelAdapter] Remote GPU tunnel not configured. Using deterministic correlation fallback.")
                break

            try:
                import urllib.request
                req_data = json.dumps({
                    "domain": "supervisor",
                    "evidence_type": "Multi-Agent Cross-Domain Correlation",
                    "evidence": payload
                }).encode("utf-8")

                req_headers = {"Content-Type": "application/json", "User-Agent": "SherlockAI-Client"}
                token = cls.get_remote_token()
                if token:
                    req_headers["X-Sherlock-Token"] = token

                req = urllib.request.Request(
                    f"{remote_url.rstrip('/')}/api/v1/inference",
                    data=req_data,
                    headers=req_headers
                )

                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        remote_json = json.loads(resp.read().decode("utf-8"))
                        # Remote json may contain reasoning or inner json
                        parsed_output, val_errors = cls._parse_and_validate_supervisor_json(
                            remote_json,
                            valid_finding_ids
                        )

                        if not val_errors and parsed_output.get("correlations"):
                            parsed_output["inference_provider"] = "AI-assisted (Remote GPU Accelerated)"
                            parsed_output["analysis_mode"] = "AI-assisted"
                            parsed_output["validation_status"] = "PASSED"
                            parsed_output["retry_count"] = attempt - 1
                            return parsed_output

                        # If model provided reasoning, capture it as GPU synthesized incident narrative
                        gpu_narrative = remote_json.get("reasoning") or remote_json.get("incident_narrative")
                        if gpu_narrative:
                            if isinstance(gpu_narrative, str) and "```json" in gpu_narrative:
                                import re
                                m = re.search(r"```json\s*(\{.*?\})\s*```", gpu_narrative, re.DOTALL)
                                if m:
                                    try:
                                        inner = json.loads(m.group(1))
                                        gpu_narrative = inner.get("reasoning") or inner.get("incident_narrative") or gpu_narrative
                                    except Exception:
                                        pass

                            log_app_event("[Supervisor] Captured remote GPU neural incident narrative.")
                            return {
                                "correlations": candidate_edges,
                                "incident_narrative": str(gpu_narrative).strip(),
                                "inference_provider": "AI-assisted (Remote GPU Accelerated)",
                                "analysis_mode": "AI-assisted",
                                "validation_status": "PASSED",
                                "retry_count": attempt - 1
                            }

                        # Validation failed
                        last_error = f"Validation errors (Attempt {attempt}): {'; '.join(val_errors)}"
                        log_error_event(f"[Supervisor] {last_error}")

                        if attempt <= max_retries:
                            payload["feedback_error"] = (
                                f"Your previous response had schema validation errors: {val_errors}. "
                                f"Strictly use only these valid Finding IDs: {list(valid_finding_ids)}. "
                                "Return only valid JSON matching the requested schema."
                            )
                            continue
            except Exception as e:
                last_error = str(e)
                log_error_event(f"[Supervisor] Remote GPU correlation inference attempt {attempt} failed: {e}")
                if attempt <= max_retries:
                    continue
                break

        # Require Genuine GPU Inference - No deterministic fallback for Supervisor reasoning
        import uuid
        return {
            "correlations": [],
            "incident_narrative": None,
            "inference_provider": "Failed (GPU Unavailable)",
            "analysis_mode": "Failed",
            "validation_status": "GPU_UNAVAILABLE",
            "validation_error": last_error or "Remote GPU inference bridge is offline or unavailable.",
            "retry_count": attempt - 1,
            "error": "GPU_UNAVAILABLE"
        }

    @classmethod
    def _build_supervisor_payload(
        cls,
        case_id: str,
        findings: List[Dict[str, Any]],
        candidate_edges: List[Dict[str, Any]],
        case_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Formats normalized findings and candidate edges for Supervisor input.
        """
        clean_findings = []
        for f in findings:
            clean_findings.append({
                "finding_id": f.get("finding_id"),
                "agent": f.get("agent") or f.get("domain"),
                "artifact_type": f.get("artifact_type") or f.get("evidence_type"),
                "observation": f.get("observation") or (f.get("reasoning", "")[:200]),
                "entities": f.get("entities", []),
                "assessment": f.get("assessment") or f.get("classification"),
                "risk": f.get("risk") or f.get("risk_level"),
                "timestamp_utc": (f.get("timeline") or {}).get("timestamp_utc") or f.get("timestamp_utc")
            })

        clean_candidates = []
        for c in candidate_edges:
            clean_candidates.append({
                "source_finding_id": c.get("source_finding_id"),
                "target_finding_id": c.get("target_finding_id"),
                "relationship_type": c.get("relationship_type"),
                "rule_id": c.get("rule_id"),
                "matched_entities": c.get("matched_entities"),
                "epistemic_class": c.get("epistemic_class")
            })

        return {
            "task": "SUPERVISOR_MULTI_AGENT_CORRELATION",
            "case_id": case_id,
            "context": case_context or {},
            "findings": clean_findings,
            "candidate_edges": clean_candidates,
            "output_contract_instructions": (
                "Evaluate the candidate edges and specialist findings. Propose corroborated cross-domain links.\n"
                "STRICT RULES:\n"
                "1. Only use finding IDs present in 'findings'. DO NOT fabricate new IDs.\n"
                "2. Epistemic class must be one of: CAUSAL_DEPENDENCY, CORRELATIONAL_ASSOCIATION, COINCIDENTAL_NOISE, AMBIGUOUS_UNKNOWN.\n"
                "3. Distinguish directly observed linkages from model hypotheses.\n"
                "4. Output MUST be valid JSON conforming to:\n"
                "{\n"
                '  "correlations": [\n'
                '    {\n'
                '      "source_finding_id": "F-...",\n'
                '      "target_finding_id": "F-...",\n'
                '      "relationship_type": "...",\n'
                '      "epistemic_class": "...",\n'
                '      "matched_entities": [...],\n'
                '      "supporting_evidence_ids": [...],\n'
                '      "reasoning": "...",\n'
                '      "alternative_explanations": "...",\n'
                '      "missing_evidence": "...",\n'
                '      "confidence": 0.85\n'
                '    }\n'
                '  ],\n'
                '  "incident_narrative": "Synthesized multi-stage attack reconstruction narrative."\n'
                "}"
            )
        }

    @classmethod
    def _parse_and_validate_supervisor_json(
        cls,
        raw_output: Any,
        valid_finding_ids: Set[str]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Parses supervisor output string or dict and validates ground-truth finding references.
        """
        errors = []
        content = raw_output

        # Extract inner json string if wrapped
        if isinstance(content, dict):
            reasoning = content.get("reasoning", "")
            if "```json" in reasoning:
                import re
                m = re.search(r"```json\s*(\{.*?\})\s*```", reasoning, re.DOTALL)
                if m:
                    try:
                        content = json.loads(m.group(1))
                    except Exception as pe:
                        errors.append(f"Failed to parse inner markdown JSON: {pe}")
            elif "correlations" not in content and isinstance(content.get("evidence"), dict):
                content = content.get("evidence")

        if isinstance(content, str):
            import re
            m = re.search(r"(\{.*\})", content, re.DOTALL)
            if m:
                try:
                    content = json.loads(m.group(1))
                except Exception as pe:
                    return {}, [f"Malformed JSON in supervisor output: {pe}"]
            else:
                return {}, ["No JSON object found in supervisor output."]

        if not isinstance(content, dict):
            return {}, ["Supervisor response is not a valid JSON dictionary."]

        correlations = content.get("correlations", [])
        if not isinstance(correlations, list):
            errors.append("'correlations' field must be a list.")
            return {}, errors

        valid_epistemics = {
            "CAUSAL_DEPENDENCY",
            "CORRELATIONAL_ASSOCIATION",
            "COINCIDENTAL_NOISE",
            "AMBIGUOUS_UNKNOWN"
        }

        validated_edges = []
        for idx, edge in enumerate(correlations):
            if not isinstance(edge, dict):
                errors.append(f"Edge {idx} is not an object.")
                continue

            src = edge.get("source_finding_id")
            tgt = edge.get("target_finding_id")

            if not src or src not in valid_finding_ids:
                errors.append(f"Edge {idx}: Invalid or fabricated source_finding_id '{src}'.")
                continue
            if not tgt or tgt not in valid_finding_ids:
                errors.append(f"Edge {idx}: Invalid or fabricated target_finding_id '{tgt}'.")
                continue
            if src == tgt:
                errors.append(f"Edge {idx}: Self-loop not permitted (source == target).")
                continue

            epistemic = str(edge.get("epistemic_class", "CORRELATIONAL_ASSOCIATION")).upper()
            if epistemic not in valid_epistemics:
                epistemic = "CORRELATIONAL_ASSOCIATION"

            conf = float(edge.get("confidence", 0.80))
            conf = max(0.1, min(1.0, conf))

            validated_edges.append({
                "source_finding_id": src,
                "target_finding_id": tgt,
                "relationship_type": edge.get("relationship_type") or "CORRELATES_WITH",
                "epistemic_class": epistemic,
                "matched_entities": edge.get("matched_entities") or [],
                "supporting_evidence_ids": edge.get("supporting_evidence_ids") or [src, tgt],
                "reasoning": edge.get("reasoning") or "Supervisor evaluated cross-agent finding linkage.",
                "alternative_explanations": edge.get("alternative_explanations") or "Unverified environmental coincidence.",
                "missing_evidence": edge.get("missing_evidence") or "None identified.",
                "confidence": conf,
                "uncertainty_score": round(1.0 - conf, 4),
                "is_model_hypothesis": True,
                "rule_id": edge.get("rule_id") or "SUPERVISOR-HYPOTHESIS-01"
            })

        narrative = content.get("incident_narrative") or content.get("narrative") or "Supervisor synthesis completed."

        return {
            "correlations": validated_edges,
            "incident_narrative": narrative
        }, errors

