from datetime import datetime
from urllib.request import Request

from fastapi import APIRouter, HTTPException
from starlette.status import HTTP_409_CONFLICT, HTTP_201_CREATED, HTTP_500_INTERNAL_SERVER_ERROR

from app import schemas
from app.db import User
from app.schemas import UserResponseSchema
from app.serializers.user import get_serialized_user
from app.utils import generate_verification_code, check_user_exists, hash_password, validate_password, \
    construct_verification_url, send_verification_email

router = APIRouter()


@router.post('/register', status_code=HTTP_201_CREATED)
async def create_user(payload: schemas.CreateUserSchema, request: Request):
    # Check if user already exists
    if await check_user_exists(payload.email):
        raise HTTPException(status_code=HTTP_409_CONFLICT, detail='Account already exists')

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
        raise HTTPException(status_code=HTTP_500_INTERNAL_SERVER_ERROR, detail=error)

    return {'status': 'success', 'message': 'Verification token successfully sent to your email'}