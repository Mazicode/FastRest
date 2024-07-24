import hashlib
import os
import random
from datetime import datetime, timedelta

import jwt
from fastapi import HTTPException, Request
from jwt import ExpiredSignatureError, InvalidTokenError

from passlib.context import CryptContext
from pydantic import EmailStr
from starlette import status
from starlette.status import HTTP_400_BAD_REQUEST

from app import schemas
from app.send_email import Email
from app.routers import auth
from app.serializers.user import get_serialized_user

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(password: str, hashed_password: str):
    return pwd_context.verify(password, hashed_password)


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
    return f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verify_email/{token}"


async def send_verification_email(user: schemas.UserResponseSchema, url: str, email: EmailStr) -> None:
    await Email(get_serialized_user(user), url, [email]).send_verification_code()


def create_token(data: dict, expires_delta: timedelta = None, token_type: str = "access"):
    to_encode = data.copy()
    if token_type == "access":
        expire = datetime.utcnow() + (
            expires_delta if expires_delta else timedelta(minutes=auth.ACCESS_TOKEN_EXPIRES_IN))
    elif token_type == "refresh":
        expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=7))
    else:
        raise ValueError("Invalid token type")

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM"))

    return encoded_jwt


def is_valid_token(token: str) -> bool:
    """
    Check if a string is a valid JWT token.

    :param token: The token string to validate
    :return: True if the token is valid, False otherwise
    """
    try:
        # Attempt to decode the token
        jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("JWT_ALGORITHM")])
        return True
    except (ExpiredSignatureError, InvalidTokenError) as e:
        print(f"Token validation error: {e}")
        return False


def decode_token(token: str):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("JWT_ALGORITHM")])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
