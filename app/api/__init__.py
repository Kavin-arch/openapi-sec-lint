"""HTTP API routes, re-exported for the application entry point."""

from app.api.scans import router

__all__ = ["router"]
