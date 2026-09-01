"""
Request Audit Logger Middleware for HMACFR.

Logs incoming API request paths, HTTP methods, client IPs, and status codes.
"""

import time
from fastapi import Request
from app.core.logger import app_logger


async def request_logger_middleware(request: Request, call_next):
    """
    Middleware logging API execution latency and status codes.
    """
    start_time = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    client_ip = request.client.host if request.client else "127.0.0.1"
    
    msg = f"HTTP {request.method} {request.url.path} | Client: {client_ip} | Status: {response.status_code} | {duration_ms}ms"
    app_logger.info(msg)
    return response
