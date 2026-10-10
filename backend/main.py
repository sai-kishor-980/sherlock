"""
H-MACFR Backend Application Entry Point.

Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework.
Configures FastAPI app factory, lifespan context manager, CORS middleware,
centralized exception handlers, and API route registrations.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.core.config import settings
from app.core.logger import log_error_event, log_app_event
from app.core.exceptions import HMACFRError
from app.db.connection import engine, Base, SessionLocal
from app.services.vault_service import EvidenceVaultService
from app.db.repositories.user_repo import UserRepository
from app.core.security import get_password_hash
from app.api.router import api_router


def ensure_db_migrations():
    import sqlite3
    db_file = getattr(settings, "DATABASE_URL", "sqlite:///./hmacfr.db").replace("sqlite:///", "")
    if os.path.exists(db_file):
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(cases)")
            cols = [r[1] for r in cursor.fetchall()]
            if cols:
                if "deletion_reason" not in cols:
                    cursor.execute("ALTER TABLE cases ADD COLUMN deletion_reason TEXT")
                if "deletion_requested_by" not in cols:
                    cursor.execute("ALTER TABLE cases ADD COLUMN deletion_requested_by TEXT")
                conn.commit()
            conn.close()
        except Exception as e:
            log_error_event(f"Error during SQLite schema migration: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifespan Context Manager.
    Handles startup DB initialization, default user seeding, and graceful shutdown.
    """
    log_app_event("Starting H-MACFR Forensic Application Lifespan Services...")
    
    # 1. Ensure DB Tables Exist & Missing Columns Migrated
    ensure_db_migrations()
    Base.metadata.create_all(bind=engine)
    EvidenceVaultService.ensure_vault_structure()
    
    # 2. Seed Default Investigator & Admin Accounts if missing
    db = SessionLocal()
    try:
        admin_hash = get_password_hash("Admin@2026")
        inv_hash = get_password_hash("Investigator@2026")
        UserRepository.seed_default_users(db, investigator_hash=inv_hash, admin_hash=admin_hash)

        # 3. Seed Default Sample Forensic Cases for Extraction & Output Demonstration
        from app.db.models.case import Case
        sample_cases = [
            ("Bharath_TES1", "RAM Memory Forensic Scan (Cridex)", "Investigator 01", "Volatile memory dump inspection with Volatility 3, pslist, and malfind detections.", "Critical"),
            ("DISK_1", "Windows Disk Artifact Analysis", "Investigator 01", "Forensic extraction of Windows Registry, Prefetch, USB devices, and MFT records.", "High")
        ]
        for c_id, c_name, c_inv, c_desc, c_prio in sample_cases:
            existing = db.query(Case).filter(Case.case_id == c_id).first()
            if not existing:
                db.add(Case(case_id=c_id, case_name=c_name, investigator_name=c_inv, description=c_desc, priority=c_prio, status="Active"))
        db.commit()
    except Exception as e:
        log_error_event(f"Error seeding default application accounts: {str(e)}")
        db.rollback()
    finally:
        db.close()

    yield

    log_app_event("Shutting down H-MACFR Forensic Application Lifespan Services...")


def create_app() -> FastAPI:
    """
    FastAPI Application Factory.
    """
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description="Hierarchical Multi-Agent Cognitive Forensic Reconstruction Framework API",
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        docs_url=f"{settings.API_V1_STR}/docs",
        redoc_url=f"{settings.API_V1_STR}/redoc",
        lifespan=lifespan
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=getattr(settings, "CORS_ORIGINS", ["*"]),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


    # Central Domain Exception Handler
    @app.exception_handler(HMACFRError)
    async def hmacfr_exception_handler(request: Request, exc: HMACFRError):
        log_error_event(f"Domain Error on {request.url.path}: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": exc.message, "info": exc.details}
        )

    # Include Central API Router
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Explicit Logo Route handlers for Logo.png, Logo.jpg, Logo.svg
    @app.get("/Logo.png", tags=["Assets"])
    @app.get("/ui/Logo.png", tags=["Assets"])
    @app.get("/images/Logo.png", tags=["Assets"])
    @app.get("/ui/images/Logo.png", tags=["Assets"])
    def get_app_logo_png():
        logo_path = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "frontend", "images", "Logo.png"))
        if os.path.exists(logo_path):
            return FileResponse(logo_path, media_type="image/png")
        root_logo = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "Logo.png"))
        if os.path.exists(root_logo):
            return FileResponse(root_logo, media_type="image/png")
        return JSONResponse(status_code=404, content={"detail": "Logo.png not found"})

    @app.get("/Logo.jpg", tags=["Assets"])
    @app.get("/ui/Logo.jpg", tags=["Assets"])
    @app.get("/images/Logo.jpg", tags=["Assets"])
    @app.get("/ui/images/Logo.jpg", tags=["Assets"])
    def get_app_logo_jpg():
        logo_path = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "frontend", "images", "Logo.jpg"))
        if os.path.exists(logo_path):
            return FileResponse(logo_path, media_type="image/jpeg")
        root_logo = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "Logo.jpg"))
        if os.path.exists(root_logo):
            return FileResponse(root_logo, media_type="image/jpeg")
        return JSONResponse(status_code=404, content={"detail": "Logo.jpg not found"})

    @app.get("/Logo.svg", tags=["Assets"])
    @app.get("/ui/Logo.svg", tags=["Assets"])
    def get_app_logo_svg():
        logo_path = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "frontend", "images", "Logo.png"))
        if os.path.exists(logo_path):
            return FileResponse(logo_path, media_type="image/png")
        jpg_logo = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "frontend", "images", "Logo.jpg"))
        if os.path.exists(jpg_logo):
            return FileResponse(jpg_logo, media_type="image/jpeg")
        return JSONResponse(status_code=404, content={"detail": "Logo asset not found"})

    # Robust resolution of frontend directory
    base_dir = os.path.abspath(os.path.dirname(__file__))
    frontend_dir = os.path.abspath(os.path.join(base_dir, "..", "frontend"))
    if not os.path.exists(frontend_dir):
        frontend_dir = os.path.abspath(os.path.join(settings.BASE_DIR, "..", "frontend"))

    # Bulletproof Frontend Web UI Routes for /ui, /ui/, /ui/index.html & assets
    @app.get("/ui", include_in_schema=False)
    @app.get("/ui/", include_in_schema=False)
    def serve_ui_root():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse(status_code=404, content={"detail": "index.html not found"})

    @app.get("/ui/{file_path:path}", include_in_schema=False)
    def serve_ui_file(file_path: str):
        target_file = os.path.abspath(os.path.join(frontend_dir, file_path))
        if os.path.exists(target_file) and os.path.isfile(target_file) and target_file.startswith(frontend_dir):
            return FileResponse(target_file)
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return JSONResponse(status_code=404, content={"detail": f"{file_path} not found"})

    # Mount static assets for root and /ui paths (images, css, js)
    if os.path.exists(frontend_dir):
        images_dir = os.path.join(frontend_dir, "images")
        css_dir = os.path.join(frontend_dir, "css")
        js_dir = os.path.join(frontend_dir, "js")
        
        if os.path.exists(images_dir):
            app.mount("/images", StaticFiles(directory=images_dir), name="images")
            app.mount("/ui/images", StaticFiles(directory=images_dir), name="ui_images")
        if os.path.exists(css_dir):
            app.mount("/css", StaticFiles(directory=css_dir), name="css")
            app.mount("/ui/css", StaticFiles(directory=css_dir), name="ui_css")
        if os.path.exists(js_dir):
            app.mount("/js", StaticFiles(directory=js_dir), name="js")
            app.mount("/ui/js", StaticFiles(directory=js_dir), name="ui_js")

        app.mount("/static", StaticFiles(directory=frontend_dir, html=True), name="static")


    @app.get("/", tags=["Health Check"])
    def root():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {
            "message": f"Welcome to {settings.PROJECT_NAME}",
            "version": "1.0.0",
            "ui": "/ui/",
            "docs": f"{settings.API_V1_STR}/docs"
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
