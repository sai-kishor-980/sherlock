"""
Global Exception Handler Middleware for HMACFR.

Catches unhandled server errors, logs detailed stack traces to error.log, and returns structured JSON error responses.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.logger import log_error_event


async def global_exception_handler_middleware(request: Request, call_next):
    """
    Middleware wrapping HTTP requests with unhandled exception logging.
    """
    try:
        response = await call_next(request)
        return response
    except Exception as exc:
        err_msg = f"Unhandled Exception on {request.method} {request.url.path}: {str(exc)}"
        log_error_event(err_msg, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error", "path": str(request.url.path)}
        )
