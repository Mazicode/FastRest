from fastapi import Request

from slowapi.errors import RateLimitExceeded
from starlette.responses import JSONResponse

from app.main import api


@api.exception_handler(RateLimitExceeded)
async def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded, try again later."}
    )
