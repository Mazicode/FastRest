import base64
from typing import List
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from starlette import status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
from bson import ObjectId

from app.serializers.user import get_serialized_user

from .db import User
from .config import settings
from .schemas import UserResponseSchema


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = base64.b64decode(
        settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(
        settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def get_user_from_jwt(user_id: str) -> UserResponseSchema:
    user = get_serialized_user(User.find_one({'_id': ObjectId(str(user_id))}))

    if not user:
        raise UserNotFound('User no longer exists')

    if not user["verified"]:
        raise NotVerified('You are not verified')

    return user


def require_user(authorize: AuthJWT = Depends()) -> UserResponseSchema:
    try:
        # Ensure the JWT is present and valid
        authorize.jwt_required()

        # Extract user ID from the token
        user_id = authorize.get_jwt_subject()

        # Retrieve and validate the user
        user = get_user_from_jwt(user_id)

    except Exception as e:
        error = e.__class__.__name__
        print(f"Exception occurred: {error}")

        if error == 'MissingTokenError':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in'
            )
        if error == 'UserNotFound':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='User no longer exists'
            )
        if error == 'NotVerified':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account'
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired'
        )

    return user
