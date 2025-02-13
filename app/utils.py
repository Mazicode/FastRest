import hashlib
import random
from datetime import datetime, timedelta

import jwt
from fastapi import HTTPException, Request, Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from jwt import ExpiredSignatureError, InvalidTokenError

from passlib.context import CryptContext
from pydantic import EmailStr
from starlette import status
from starlette.status import HTTP_400_BAD_REQUEST

from app import schemas
from app.config import settings
from app.db.models import User
from app.send_email import Email
from app.serializers.user import get_serialized_user

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def validate_password(password: str, password_confirm: str) -> None:
    if password != password_confirm:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST, detail='Passwords do not match')


def generate_verification_code() -> str:
    token = random.randbytes(10)
    hashed_code = hashlib.sha256(token).hexdigest()

    return hashed_code


def construct_verification_url(request: Request, token: str) -> str:
    return f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/auth/verify_email/{token}"


async def send_verification_email(user: schemas.UserBase, url: str, email: EmailStr) -> None:
    await Email(get_serialized_user(user), url, [email]).send_verification_code()


def is_valid_token(token: str) -> bool:
    """
    Check if a string is a valid JWT token.

    :param token: The token string to validate
    :return: True if the token is valid, False otherwise
    """
    try:
        # Attempt to decode the token
        jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return True
    except (ExpiredSignatureError, InvalidTokenError) as e:
        print(f"Token validation error: {e}")
        return False


def decode_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
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


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(settings.ACCESS_TOKEN_EXPIRES_IN)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    return encoded_jwt


def create_refresh_token(data: dict):
    expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRES_IN)
    to_encode = data.copy()
    to_encode.update({"exp": expires})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Dependency to get the current user from the JWT token
def get_current_user(credentials: HTTPAuthorizationCredentials = Security(bearer_scheme)) -> User:
    return decode_token(credentials.credentials)


# Role-based access control decorator
def require_role(role: str):
    def role_checker(user: User = Depends(get_current_user)):
        if user.role != role:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user

    return role_checker
