from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import auth, user

app = FastAPI()

base_path = '/api'

origins = [
    settings.CLIENT_ORIGIN,
]

CORSMiddleware(
    app,
    allow_origins=(),
    allow_methods="GET",
    allow_headers=(),
    allow_credentials=False,
    allow_origin_regex=None,
    expose_headers=(),
    max_age=600,
)

app.include_router(auth.router, tags=['Auth'], prefix=f"{base_path}/auth")
app.include_router(user.router, tags=['Users'], prefix=f"{base_path}/users")
