import os
from datetime import datetime
import jwt
from fastapi import Request, Response

from fastapi import APIRouter, HTTPException
from fastapi.security import OAuth2PasswordBearer
from fastapi_jwt import JwtAccessBearer
from jwt import ExpiredSignatureError, InvalidTokenError
from starlette import status

from app import schemas
from app.config import settings
from app.db import check_user_exists, Users
from app.schemas import VerifyEmailResponse, Token
from app.serializers.user import get_serialized_user
from app.utils import generate_verification_code, hash_password, validate_password, \
    construct_verification_url, send_verification_email, verify_password, create_token, decode_token, is_valid_token

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN

access_token_jwt = JwtAccessBearer(secret_key="your-secret-key", access_expires_delta=ACCESS_TOKEN_EXPIRES_IN)
refresh_token_jwt = JwtAccessBearer(secret_key="your-secret-key", access_expires_delta=REFRESH_TOKEN_EXPIRES_IN)


@router.post('/signup',
             status_code=status.HTTP_201_CREATED,
             summary="Register a new user",
             description="Registers a new user by creating a new user entry in the database. Validates the user "
                         "input, hashes the password, and sends a verification email to the user with a verification "
                         "token. If an error occurs during email sending, the verification code is cleaned up.",
             response_description="Successful registration returns a status message indicating that a verification "
                                  "token was sent to the user's email.",
             responses={
                 status.HTTP_201_CREATED: {
                     "description": "User registered successfully and verification email sent.",
                     "content": {
                         "application/json": {
                             "example": {
                                 "status": "success",
                                 "message": "Verification token successfully sent to your email"
                             }
                         }
                     }
                 },
                 status.HTTP_400_BAD_REQUEST: {
                     "description": "Validation error for provided input.",
                     "content": {
                         "application/json": {
                             "example": {
                                 "detail": "Passwords do not match"
                             }
                         }
                     }
                 },
                 status.HTTP_409_CONFLICT: {
                     "description": "Conflict error when trying to register with an existing email.",
                     "content": {
                         "application/json": {
                             "example": {
                                 "detail": "Account already exists"
                             }
                         }
                     }
                 },
                 status.HTTP_500_INTERNAL_SERVER_ERROR: {
                     "description": "Server error if something goes wrong during email sending.",
                     "content": {
                         "application/json": {
                             "example": {
                                 "detail": "An unexpected error occurred"
                             }
                         }
                     }
                 }
             })
async def create_user(payload: schemas.CreateUserSchema, request: Request):
    # Check if user already exists
    if await check_user_exists(payload.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='Account already exists')

    # Validate passwords
    validate_password(payload.password, payload.password_confirm)

    # Prepare user data
    hashed_password = hash_password(payload.password)
    user_data = {
        'full_name': payload.full_name,
        'email': payload.email.lower(),
        'role': 'user',
        'verified': False,
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow(),
        'password': hashed_password
    }

    # Insert user into database
    result = Users.insert_one(user_data)
    new_user = Users.find_one({'_id': result.inserted_id})

    try:
        # Generate and save verification code
        verification_code = generate_verification_code()
        Users.find_one_and_update(
            {"_id": result.inserted_id},
            {"$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}}
        )

        # Construct verification URL
        verification_url = construct_verification_url(request, verification_code)

        # Send verification email
        await send_verification_email(new_user, verification_url, payload.email)
    except Exception as error:
        # Handle email sending failure and clean up verification code
        Users.find_one_and_update(
            {"_id": result.inserted_id},
            {"$set": {"verification_code": None, "updated_at": datetime.utcnow()}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error.__dict__)

    return {'status': 'success', 'message': 'Verification token successfully sent to your email'}


@router.post('/login', summary="Login User", response_description="Access and refresh tokens", responses={
    200: {"description": "Successful login",
          "content": {"application/json": {"example": {"status": "success", "access_token": "your_access_token"}}}},
    400: {"description": "Incorrect Email or Password",
          "content": {"application/json": {"example": {"detail": "Incorrect Email or Password"}}}},
    401: {"description": "Please verify your email address",
          "content": {"application/json": {"example": {"detail": "Please verify your email address"}}}}
})
def login(payload: schemas.LoginUserSchema, response: Response):
    # Check if the user exists
    db_user = Users.find_one({'email': payload.email.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')

    user = get_serialized_user(db_user)

    # Check if the user has verified their email
    if not user['verified']:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your email address')

    # Check if the password is valid
    if not verify_password(payload.password, user['password']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect Email or Password')

    # Create access and refresh tokens
    access_token = create_token(data={"email": user['email']})
    refresh_token = create_token(data={"email": user['email']}, token_type="refresh")

    # Set the refresh token in an HTTP-only cookie
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True)

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token, ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        REFRESH_TOKEN_EXPIRES_IN * 60, REFRESH_TOKEN_EXPIRES_IN * 60, '/', None, False, True, 'lax')
    response.set_cookie('logged_in', 'True', ACCESS_TOKEN_EXPIRES_IN * 60,
                        ACCESS_TOKEN_EXPIRES_IN * 60, '/', None, False, False, 'lax')

    return {'status': 'success', 'access_token': access_token}


@router.post("/refresh_token")
async def refresh_token(payload: Token):
    if not is_valid_token(payload.access_token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token data"
        )
    try:
        payload_data = decode_token(payload.access_token)
        user_email = payload_data.get("email")

        if not user_email or payload.email != user_email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="user not recognized"
            )

        new_access_token = create_token(data={"email": user_email})
        return {"access_token": new_access_token, "token_type": "bearer"}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during token refresh {e}"
        )


@router.get('/verify_email/{token}', response_model=VerifyEmailResponse, summary="Verify Email",
            description="Verifies the user's email using the provided JWT token.",
            responses={
                200: {
                    "description": "Account verified successfully",
                    "content": {
                        "application/json": {
                            "example": {
                                "status": "success",
                                "message": "Account verified successfully"
                            }
                        }
                    }
                },
                403: {
                    "description": "Invalid or expired token",
                    "content": {
                        "application/json": {
                            "example": {
                                "detail": "Invalid verification code or account already verified"
                            }
                        }
                    }
                }
            })
def verify_token(token: str):
    try:
        payload = jwt.decode(token, os.getenv("SECRET_KEY"), algorithms=[os.getenv("JWT_ALGORITHM")])
        user_email = payload.get("sub")

        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid verification code"
            )

        result = Users.find_one_and_update(
            {"email": user_email},
            {
                "$set": {
                    "verification_code": None,
                    "verified": True,
                    "updated_at": datetime.utcnow()
                }
            },
            return_document=True
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid verification code or account already verified"
            )

        return {
            "status": "success",
            "message": "Account verified successfully"
        }

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verification token has expired"
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid verification token"
        )
