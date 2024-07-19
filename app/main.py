from fastapi import FastAPI
from fastapi import CORSMiddleware

from app.config import settings
from app.routers import auth, user

app = FastAPI()
base_path = '/api'

origins = [
    settings.CLIENT_ORIGIN,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, tags=['Auth'], prefix=f"{base_path}/auth")
app.include_router(user.router, tags=['Users'], prefix=f"{base_path}/users")
