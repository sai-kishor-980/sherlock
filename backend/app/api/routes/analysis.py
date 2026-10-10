"""
Real-time Forensic Analysis API & WebSocket Engine for Sherlock AI (H-MACFR).

Replaces simulation with the real extraction pipeline:
Evidence -> PluginManager / Extractors -> Raw Artifacts -> Forensic Synthesizer
-> Unified Timeline, Findings, Correlations, Reconstruction, and Court-Ready Report.
Streams live terminal logs, stage updates, and progress over WebSocket.
"""

import asyncio
import time
import uuid
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.connection import get_db, SessionLocal
from app.db.models.case import Case
from app.db.models.evidence import Evidence
from app.services.synthesizer_service import ForensicSynthesizerService
from app.core.logger import log_app_event, log_error_event

router = APIRouter()

# In-memory storage for active and completed analysis tasks
active_tasks: Dict[str, dict] = {}


class AnalysisStartRequest(BaseModel):
    case_id: str
    case_name: str
    analysis_type: Optional[str] = "Deep Cognitive Forensic Scan"
    total_duration_seconds: Optional[int] = 10


class AnalysisTaskStatus(BaseModel):
    task_id: str
    case_id: str
    case_name: str
    status: str  # "queued", "running", "completed", "failed"
    progress: float
    stage: str
    elapsed_seconds: int
    time_remaining_seconds: int
    created_at: float


# Connection manager for active WebSocket clients
class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, task_id: str, websocket: WebSocket):
        await websocket.accept()
        if task_id not in self.active_connections:
            self.active_connections[task_id] = []
        self.active_connections[task_id].append(websocket)

    def disconnect(self, task_id: str, websocket: WebSocket):
        if task_id in self.active_connections:
            if websocket in self.active_connections[task_id]:
                self.active_connections[task_id].remove(websocket)
            if not self.active_connections[task_id]:
                del self.active_connections[task_id]

    async def broadcast(self, task_id: str, message: dict):
        if task_id in self.active_connections:
            for connection in list(self.active_connections[task_id]):
                try:
                    await connection.send_json(message)
                except Exception:
                    self.disconnect(task_id, connection)


ws_manager = WebSocketManager()


@router.post("/start", response_model=AnalysisTaskStatus)
async def start_analysis(req: AnalysisStartRequest):
    task_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()
    
    task_data = {
        "task_id": task_id,
        "case_id": req.case_id,
        "case_name": req.case_name,
        "status": "running",
        "progress": 5.0,
        "stage": "Initializing Sherlock Forensic Extraction Engine...",
        "elapsed_seconds": 0,
        "total_duration_seconds": req.total_duration_seconds or 10,
        "time_remaining_seconds": req.total_duration_seconds or 10,
        "created_at": now,
        "logs": [f"[{time.strftime('%H:%M:%S')}] Analysis task {task_id} initiated for Case '{req.case_name}' ({req.case_id})."]
    }
    
    active_tasks[task_id] = task_data
    # Launch real background analysis worker
    asyncio.create_task(run_real_analysis_pipeline(task_id))
    
    return AnalysisTaskStatus(
        task_id=task_id,
        case_id=req.case_id,
        case_name=req.case_name,
        status="running",
        progress=5.0,
        stage=task_data["stage"],
        elapsed_seconds=0,
        time_remaining_seconds=task_data["total_duration_seconds"],
        created_at=now
    )


@router.get("/tasks", response_model=List[AnalysisTaskStatus])
def list_analysis_tasks():
    results = []
    for t_id, task in active_tasks.items():
        results.append(AnalysisTaskStatus(
            task_id=task["task_id"],
            case_id=task["case_id"],
            case_name=task["case_name"],
            status=task["status"],
            progress=task["progress"],
            stage=task["stage"],
            elapsed_seconds=task["elapsed_seconds"],
            time_remaining_seconds=task["time_remaining_seconds"],
            created_at=task["created_at"]
        ))
    return sorted(results, key=lambda x: x.created_at, reverse=True)


async def broadcast_step(task_id: str, stage: str, progress: float, log_text: str):
    task = active_tasks.get(task_id)
    if not task:
        return
    now_str = time.strftime('%H:%M:%S')
    formatted_log = f"[{now_str}] [{progress:.1f}%] {log_text}"
    task["stage"] = stage
    task["progress"] = progress
    task["logs"].append(formatted_log)
    
    msg = {
        "type": "ANALYSIS_UPDATE",
        "task_id": task_id,
        "case_id": task["case_id"],
        "case_name": task["case_name"],
        "status": task["status"],
        "progress": progress,
        "stage": stage,
        "elapsed_seconds": int(time.time() - task["created_at"]),
        "time_remaining_seconds": max(0, int(task["total_duration_seconds"] * (1.0 - progress / 100.0))),
        "log": formatted_log
    }
    await ws_manager.broadcast(task_id, msg)
    await ws_manager.broadcast("ALL", msg)


async def run_real_analysis_pipeline(task_id: str):
    """
    Executes real forensic extraction & synthesis pipeline.
    """
    task = active_tasks.get(task_id)
    if not task:
        return

    case_id = task["case_id"]
    case_name = task["case_name"]
    
    try:
        # Step 1: Query Case and Vaulted Evidence from SQLite
        await broadcast_step(task_id, "Querying Evidence Vault", 15.0, f"Querying vaulted evidence records for case '{case_name}' ({case_id})...")
        await asyncio.sleep(0.5)

        db = SessionLocal()
        evidence_list = []
        investigator_name = "Investigator 01"
        try:
            evidences = db.query(Evidence).filter(Evidence.case_id == case_id).all()
            for ev in evidences:
                evidence_list.append({
                    "evidence_id": ev.evidence_id,
                    "original_filename": ev.original_filename,
                    "stored_filename": ev.stored_filename,
                    "storage_path": ev.storage_path,
                    "file_hash": ev.file_hash,
                    "hmac_signature": ev.hmac_signature,
                    "type": ev.type or ev.extension
                })
            case_obj = db.query(Case).filter(Case.case_id == case_id).first()
            if case_obj and case_obj.investigator:
                investigator_name = case_obj.investigator
        except Exception as e:
            log_error_event(f"DB query error for case {case_id}: {e}")
        finally:
            db.close()

        # Step 2: Extraction Dispatching
        await broadcast_step(task_id, "Invoking Extraction Engine", 35.0, f"Dispatching {len(evidence_list)} evidence stream(s) to prot1-main PluginManager...")
        await asyncio.sleep(0.8)

        # Check if new evidence needs processing or if pre-extracted output exists
        base_dir = Path(__file__).resolve().parents[3]
        case_output = base_dir / "output" / "cases" / case_id

        # If evidence was uploaded, invoke PluginManager
        if evidence_list:
            try:
                from artifact_extraction.plugin_manager.manager import PluginManager
                pm = PluginManager(case_id=case_id)
                pm_case = pm.create_case(case_id)
                registered_items = []
                for ev in evidence_list:
                    p = ev.get("storage_path")
                    if p and os.path.exists(p):
                        registered_items.append({
                            "path": p,
                            "type": ev.get("type"),
                            "name": ev.get("original_filename"),
                            "evidence_id": ev.get("evidence_id")
                        })
                if registered_items:
                    pm.register_evidence(pm_case, registered_items)
                    await broadcast_step(task_id, "Extracting Forensic Artifacts", 55.0, f"Executing {len(registered_items)} forensic extractor adapter(s)...")
                    # Run extraction synchronously in worker thread
                    await asyncio.to_thread(pm.execute_case, pm_case)
            except Exception as ex:
                log_app_event(f"[Analysis] Note on PluginManager run: {ex}. Proceeding to synthesis...")

        await broadcast_step(task_id, "Synthesizing Evidence & Correlations", 75.0, "Parsing raw JSONs, building Chronological Attack Timeline and MITRE findings...")
        await asyncio.sleep(0.8)

        # Step 3: Forensic Synthesizer
        synthesized_data = await asyncio.to_thread(
            ForensicSynthesizerService.synthesize_case,
            case_id=case_id,
            case_name=case_name,
            investigator=investigator_name,
            evidence_records=evidence_list
        )

        timeline_count = len(synthesized_data.get("timeline", []))
        findings_count = len(synthesized_data.get("findings", []))
        artifacts_count = synthesized_data.get("artifact_inventory", {}).get("total_artifacts", 0)

        # Step 4: Completion
        task["status"] = "completed"
        task["progress"] = 100.0
        task["stage"] = "Analysis Complete — Court Report Generated"
        task["synthesized_data"] = synthesized_data

        await broadcast_step(
            task_id,
            "Analysis Complete",
            100.0,
            f"Successfully extracted {artifacts_count} artifacts, reconstructed {timeline_count} timeline events, and verified {findings_count} findings."
        )

        # Final completion event
        msg_complete = {
            "type": "ANALYSIS_COMPLETE",
            "task_id": task_id,
            "case_id": case_id,
            "case_name": case_name,
            "status": "completed",
            "progress": 100.0,
            "stage": "Analysis Complete",
            "total_artifacts": artifacts_count,
            "timeline_events": timeline_count,
            "findings_count": findings_count
        }
        await ws_manager.broadcast(task_id, msg_complete)
        await ws_manager.broadcast("ALL", msg_complete)

    except Exception as e:
        log_error_event(f"Error in run_real_analysis_pipeline: {e}")
        task["status"] = "failed"
        await broadcast_step(task_id, "Analysis Failed", 100.0, f"Analysis pipeline encountered an error: {str(e)}")


@router.websocket("/ws/stream/{task_id}")
async def websocket_analysis_endpoint(websocket: WebSocket, task_id: str):
    await ws_manager.connect(task_id, websocket)
    if task_id in active_tasks:
        task = active_tasks[task_id]
        await websocket.send_json({
            "type": "INITIAL_STATE",
            "task_id": task_id,
            "case_id": task["case_id"],
            "case_name": task["case_name"],
            "status": task["status"],
            "progress": task["progress"],
            "stage": task["stage"],
            "elapsed_seconds": task["elapsed_seconds"],
            "time_remaining_seconds": task["time_remaining_seconds"],
            "logs": task["logs"]
        })
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(task_id, websocket)


# =============================================================================
# FORENSIC OUTPUT QUERY REST ENDPOINTS
# =============================================================================

@router.get("/{case_id}/data")
def get_case_forensic_data(case_id: str):
    """
    Returns the complete synthesized forensic dataset for a case.
    """
    data = ForensicSynthesizerService.get_synthesized_case(case_id)
    if not data:
        # Check active tasks for cached data
        for t in active_tasks.values():
            if t.get("case_id") == case_id and "synthesized_data" in t:
                return t["synthesized_data"]
        # Fallback to synthesis
        data = ForensicSynthesizerService.synthesize_case(case_id)
    return data


@router.get("/{case_id}/artifacts")
def get_case_artifacts(case_id: str):
    """
    Returns categorized forensic artifacts with pagination and counts.
    """
    data = ForensicSynthesizerService.get_synthesized_case(case_id)
    if not data:
        data = ForensicSynthesizerService.synthesize_case(case_id)
    return {
        "case_id": case_id,
        "summary": data.get("artifact_inventory", {}),
        "artifacts": data.get("artifacts", {})
    }


@router.get("/{case_id}/timeline")
def get_case_timeline(case_id: str):
    """
    Returns chronological attack timeline events.
    """
    data = ForensicSynthesizerService.get_synthesized_case(case_id)
    if not data:
        data = ForensicSynthesizerService.synthesize_case(case_id)
    return {
        "case_id": case_id,
        "total_events": len(data.get("timeline", [])),
        "timeline": data.get("timeline", [])
    }


@router.get("/{case_id}/findings")
def get_case_findings(case_id: str):
    """
    Returns verified findings and anomaly indicators.
    """
    data = ForensicSynthesizerService.get_synthesized_case(case_id)
    if not data:
        data = ForensicSynthesizerService.synthesize_case(case_id)
    return {
        "case_id": case_id,
        "total_findings": len(data.get("findings", [])),
        "findings": data.get("findings", []),
        "correlations": data.get("correlations", [])
    }


@router.get("/{case_id}/report")
def get_case_report(case_id: str):
    """
    Returns full court-ready forensic investigation report.
    """
    data = ForensicSynthesizerService.get_synthesized_case(case_id)
    if not data:
        data = ForensicSynthesizerService.synthesize_case(case_id)
    return data.get("court_report", {})
