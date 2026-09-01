"""
Analysis API & WebSocket Engine for H-MACFR.

Provides WebSocket live streaming of forensic analysis progress, stage logs,
and calculated remaining time for frontend investigator views.
"""

import asyncio
import time
import uuid
from typing import Dict, List, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status
from pydantic import BaseModel

router = APIRouter()

# In-memory storage for active and completed analysis tasks
active_tasks: Dict[str, dict] = {}


class AnalysisStartRequest(BaseModel):
    case_id: str
    case_name: str
    analysis_type: Optional[str] = "Deep Cognitive Forensic Scan"
    total_duration_seconds: Optional[int] = 30


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


@router.post("/start", response_model=AnalysisTaskStatus)
async def start_analysis(req: AnalysisStartRequest):
    task_id = f"ANL-{uuid.uuid4().hex[:8].upper()}"
    now = time.time()
    
    task_data = {
        "task_id": task_id,
        "case_id": req.case_id,
        "case_name": req.case_name,
        "status": "running",
        "progress": 0.0,
        "stage": "Initializing Sherlock Forensic Workspace...",
        "elapsed_seconds": 0,
        "total_duration_seconds": req.total_duration_seconds or 30,
        "time_remaining_seconds": req.total_duration_seconds or 30,
        "created_at": now,
        "logs": [f"[{time.strftime('%H:%M:%S')}] Analysis task {task_id} queued for Case '{req.case_name}' ({req.case_id})."]
    }
    
    active_tasks[task_id] = task_data
    # Fire background task
    asyncio.create_task(run_analysis_simulation(task_id))
    
    return AnalysisTaskStatus(
        task_id=task_id,
        case_id=req.case_id,
        case_name=req.case_name,
        status="running",
        progress=0.0,
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
    # Return sorted by newest
    return sorted(results, key=lambda x: x.created_at, reverse=True)


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


async def run_analysis_simulation(task_id: str):
    task = active_tasks.get(task_id)
    if not task:
        return

    total_secs = task["total_duration_seconds"]
    stages = [
        (0.10, "Phase 1/5: Extracting AES-256 encrypted forensic evidence payloads"),
        (0.30, "Phase 2/5: Verifying SHA-256 HMAC cryptographic chain of custody"),
        (0.55, "Phase 3/5: Running Sherlock cognitive pattern recognition heuristics"),
        (0.80, "Phase 4/5: Cross-referencing threat artifact indicators & memory dumps"),
        (0.95, "Phase 5/5: Compiling final forensic reconstruction report"),
        (1.00, "Analysis Complete: Artifact verified and stored in 3D Vault.")
    ]

    for step in range(1, total_secs + 1):
        await asyncio.sleep(1)
        elapsed = step
        rem = max(0, total_secs - elapsed)
        prog = round((elapsed / total_secs) * 100, 1)

        # Find stage
        current_stage = stages[0][1]
        for ratio, st_msg in stages:
            if (elapsed / total_secs) >= ratio:
                current_stage = st_msg

        timestamp = time.strftime('%H:%M:%S')
        log_entry = f"[{timestamp}] [{prog}%] {current_stage} | Remaining: {rem}s"
        
        task["elapsed_seconds"] = elapsed
        task["time_remaining_seconds"] = rem
        task["progress"] = prog
        task["stage"] = current_stage
        task["logs"].append(log_entry)
        
        if rem == 0:
            task["status"] = "completed"

        msg = {
            "type": "ANALYSIS_UPDATE",
            "task_id": task_id,
            "case_id": task["case_id"],
            "case_name": task["case_name"],
            "status": task["status"],
            "progress": prog,
            "stage": current_stage,
            "elapsed_seconds": elapsed,
            "time_remaining_seconds": rem,
            "log": log_entry
        }

        await ws_manager.broadcast(task_id, msg)
        await ws_manager.broadcast("ALL", msg)


@router.websocket("/ws/stream/{task_id}")
async def websocket_analysis_endpoint(websocket: WebSocket, task_id: str):
    await ws_manager.connect(task_id, websocket)
    # Send initial state immediately
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
            # Keep socket alive and listen for client messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        ws_manager.disconnect(task_id, websocket)
