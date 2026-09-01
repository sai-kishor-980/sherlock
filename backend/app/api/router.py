from fastapi import APIRouter
from app.api.routes import (
    auth, cases, upload, integrity, evidence, events,
    hashing, encryption, verification, custody, preservation, analysis
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Authorization"])
api_router.include_router(cases.router, prefix="/cases", tags=["Cases"])
api_router.include_router(upload.router, prefix="/upload", tags=["Upload"])
api_router.include_router(integrity.router, prefix="/integrity", tags=["Integrity Check"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["Evidence Catalog"])
api_router.include_router(events.router, prefix="/events", tags=["Event Notifications & Handoff"])
api_router.include_router(hashing.router, prefix="/hashing", tags=["Hashing"])
api_router.include_router(encryption.router, prefix="/encryption", tags=["Encryption"])
api_router.include_router(verification.router, prefix="/verification", tags=["Multi-Factor Audit"])
api_router.include_router(custody.router, prefix="/custody", tags=["Chain of Custody"])
api_router.include_router(preservation.router, prefix="/preservation", tags=["Evidence Preservation Layer"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["Real-time Forensic Analysis"])

