import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.config import settings
from app.routers import auth, user

api = FastAPI()
limiter = Limiter(key_func=get_remote_address)
api.add_middleware(SlowAPIMiddleware)

base_path = '/api'

origins = [
    settings.CLIENT_ORIGIN,
]

CORSMiddleware(
    api,
    allow_origins=(),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
    allow_origin_regex=None,
    expose_headers=(),
    max_age=600,
)

api.include_router(auth.router, tags=['Auth'], prefix=f"{base_path}/auth")
api.include_router(user.router, tags=['Users'], prefix=f"{base_path}/users")

if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=8000)
