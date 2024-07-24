import os
from datetime import datetime, timedelta
from functools import wraps

from bson import ObjectId
import jwt

from app.db import Users


def populate_test_users():
    users = [
        {
            '_id': ObjectId('5f5b7b9f6d6f75d482c09e1a'),
            'full_name': 'John Doe',
            'email': 'john@example.com',
            'role': 'user',
            'verified': True,
            'created_at': datetime.strptime('2021-01-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ'),
            'updated_at': datetime.strptime('2021-01-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ')
        },
        {
            '_id': ObjectId('5f5b7b9f6d6f75d482c09e1b'),
            'full_name': 'Jane Doe',
            'email': 'jane@example.com',
            'role': 'admin',
            'verified': False,
            'created_at': datetime.strptime('2021-02-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ'),
            'updated_at': datetime.strptime('2021-02-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ')
        }
    ]

    # Insert the users into the collection
    Users.insert_many(users)


def create_test_token(email: str):
    to_encode = {"sub": email, "exp": datetime.utcnow() + timedelta(minutes=30)}
    encoded_jwt = jwt.encode(to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM"))

    return encoded_jwt


def authenticated_request(email: str):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            token = create_test_token(email)
            client = kwargs.get('client')
            if client:
                client.headers.update({"Authorization": f"Bearer {token}"})
            return func(*args, **kwargs)

        return wrapper

    return decorator
