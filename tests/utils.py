from datetime import datetime

from bson import ObjectId

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
        # Add more user documents as needed
    ]

    # Insert the users into the collection
    Users.insert_many(users)
