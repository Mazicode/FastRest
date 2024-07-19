import hashlib
from random import random

from fastapi import HTTPException, Request

from passlib.context import CryptContext
from pydantic import EmailStr
from starlette.status import HTTP_400_BAD_REQUEST

from app import schemas
from app.email import Email
from app.schemas import UserBaseSchema
from app.serializers.user import get_serialized_user

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


async def check_user_exists(email: str) -> bool:
    user = UserBaseSchema.find_one({'email': email.lower()})
    return user is not None


def validate_password(password: str, password_confirm: str) -> None:
    if password != password_confirm:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST, detail='Passwords do not match'
        )


def generate_verification_code() -> str:
    token = random.randbytes(10)
    hashed_code = hashlib.sha256(token).hexdigest()
    return hashed_code


def construct_verification_url(request: Request, token: str) -> str:
    return f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verifyemail/{token}"


async def send_verification_email(user: schemas.UserResponseSchema, url: str, email: EmailStr) -> None:
    await Email(get_serialized_user(user), url, [email]).send_verification_code()
