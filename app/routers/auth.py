from datetime import datetime
from urllib.request import Request

from fastapi import APIRouter, HTTPException
from starlette import status

from app import schemas
from app.db import User
from app.utils import generate_verification_code, check_user_exists, hash_password, validate_password, \
    construct_verification_url, send_verification_email

router = APIRouter()


@router.post('/register', status_code=status.HTTP_201_CREATED,
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
    validate_password(payload.password, payload.passwordConfirm)

    # Prepare user data
    hashed_password = hash_password(payload.password)
    user_data = {
        'name': payload.name,
        'email': payload.email.lower(),
        'role': 'user',
        'verified': False,
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow(),
        'password': hashed_password
    }

    # Insert user into database
    result = User.insert_one(user_data)
    new_user = User.find_one({'_id': result.inserted_id})

    try:
        # Generate and save verification code
        verification_code = generate_verification_code()
        User.find_one_and_update(
            {"_id": result.inserted_id},
            {"$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}}
        )

        # Construct verification URL
        verification_url = construct_verification_url(request, verification_code)

        # Send verification email
        await send_verification_email(new_user, verification_url, payload.email)
    except Exception as error:
        # Handle email sending failure and clean up verification code
        User.find_one_and_update(
            {"_id": result.inserted_id},
            {"$set": {"verification_code": None, "updated_at": datetime.utcnow()}}
        )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error)

    return {'status': 'success', 'message': 'Verification token successfully sent to your email'}