from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class APIError(Exception):
    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)


_ERROR_STATUS_MAP = {
    "bad_request": 400,
    "unauthorized": 401,
    "not_found": 404,
    "server_error": 500,
}


def error_response(code: str, message: str, details: dict[str, Any] | None = None) -> JSONResponse:
    status_code = _ERROR_STATUS_MAP.get(code, 500)
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            }
        },
    )


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(APIError)
    async def _api_error_handler(_: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(
            "bad_request",
            "Request validation failed",
            {"validation_errors": exc.errors()},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            return error_response("not_found", "Route not found")
        if exc.status_code == 405:
            return error_response("bad_request", "Method not allowed")
        return error_response("server_error", "HTTP error", {"status_code": exc.status_code})

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
        return error_response("server_error", "Internal server error", {"type": exc.__class__.__name__})
