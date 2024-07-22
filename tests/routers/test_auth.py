import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from fastapi import HTTPException
from starlette import status
from starlette.testclient import TestClient

from app import schemas
from app.db import Users
from app.main import app
from app.utils import hash_password, is_valid_token
from tests.test_settings import TestSettings
from dotenv import load_dotenv

load_dotenv()

auth_route = 'api/auth'


def populate_test_user(password='pass1234', verified=True, role='user'):
    Users.insert_one({
        'full_name': 'Tester Guy',
        'email': 'tester@guy.com',
        'role': role,
        'password': password,
        'password_confirm': password,
        'verified': verified,
        'created_at': None,
        'updated_at': None,
    })


class TestCreateUser(unittest.TestCase):
    def setUp(self):
        # Patch the Settings with TestSettings before app initialization
        self.settings_patcher = patch('app.config.Settings', new=TestSettings)
        self.mocked_settings = self.settings_patcher.start()

        # Initialize the TestClient with the patched app
        self.client = TestClient(app)

        # Ensure the collection is clean before the test
        Users.delete_many({})

    def tearDown(self):
        self.settings_patcher.stop()

    @patch('app.db.check_user_exists')
    @patch('app.routes.validate_password')
    @patch('app.routes.hash_password')
    @patch('app.routes.generate_verification_code')
    @patch('app.routes.construct_verification_url')
    @patch('app.routes.send_verification_email')
    async def test_create_user_success(self, mock_send_verification_email, mock_construct_verification_url,
                                       mock_generate_verification_code, mock_hash_password,
                                       mock_validate_password, mock_check_user_exists):
        # Setup mock responses
        mock_check_user_exists.return_value = False
        mock_validate_password.return_value = None
        mock_hash_password.return_value = 'hashed_password'
        mock_generate_verification_code.return_value = 'verification_code'
        mock_construct_verification_url.return_value = 'http://testserver/api/auth/verifyemail/verification_code'
        mock_send_verification_email.return_value = None

        payload = {
            'email': 'test@example.com',
            'password': 'password',
            'password_confirm': 'password',
            'verified': True
        }

        response = self.client.post(f'{auth_route}/signup', json=payload)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.json(), {
            'status': 'success',
            'message': 'Verification token successfully sent to your email'
        })
        mock_send_verification_email.assert_called_once()

    def test_user_already_exists(self):
        # Insert a user document
        populate_test_user()

        payload = {
            'full_name': 'Tester Guy',
            'email': 'tester@guy.com',
            'password': 'pass1234',
            'password_confirm': 'pass1234',
            'verified': False
        }

        response = self.client.post(f'{auth_route}/signup', json=payload)

        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(response.json(), {'detail': 'Account already exists'})

    @patch('app.utils.validate_password')
    def test_password_mismatch(self, mock_validate_password):
        mock_validate_password.side_effect = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                                           detail='Passwords do not match')
        payload = {
            'full_name': 'Tester',
            'email': 'test@example2.com',
            'password': 'password',
            'password_confirm': 'passwor',
            'verified': False
        }

        response = self.client.post(f'{auth_route}/signup', json=payload)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.json(), {'detail': 'Passwords do not match'})

    @patch('app.routes.check_user_exists')
    @patch('app.routes.validate_password')
    @patch('app.routes.hash_password')
    @patch('app.routes.generate_verification_code')
    @patch('app.routes.construct_verification_url')
    @patch('app.routes.send_verification_email')
    @patch('app.models.User.insert_one')
    @patch('app.models.User.find_one')
    @patch('app.models.User.find_one_and_update')
    async def test_email_sending_failure(self, mock_find_one_and_update, mock_find_one, mock_insert_one,
                                         mock_send_verification_email, mock_construct_verification_url,
                                         mock_generate_verification_code, mock_hash_password,
                                         mock_validate_password, mock_check_user_exists):
        # Setup mock responses
        mock_check_user_exists.return_value = False
        mock_validate_password.return_value = None
        mock_hash_password.return_value = 'hashed_password'
        mock_generate_verification_code.return_value = 'verification_code'
        mock_construct_verification_url.return_value = 'http://testserver/api/auth/verifyemail/verification_code'
        mock_send_verification_email.side_effect = Exception('Email sending failed')
        mock_insert_one.return_value = MagicMock(inserted_id='new_user_id')
        mock_find_one.return_value = {
            '_id': 'new_user_id',
            'name': 'Test User',
            'email': 'test@example.com',
            'role': 'user',
            'verified': False,
            'verification_code': 'verification_code'
        }
        mock_find_one_and_update.return_value = None

        payload = {
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'password123',
            'passwordConfirm': 'password123'
        }

        response = self.client.post(f'{auth_route}/signup', json=payload)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.json(), {'detail': 'Email sending failed'})
        mock_find_one_and_update.assert_called_once()


class TestLogin(unittest.TestCase):
    def setUp(self):
        # Patch the Settings with TestSettings before app initialization
        self.settings_patcher = patch('app.config.Settings', new=TestSettings)
        self.mocked_settings = self.settings_patcher.start()

        # Initialize the TestClient with the patched app
        self.client = TestClient(app)

        # Ensure the collection is clean before the test
        Users.delete_many({})

    def test_login_user_not_found(self):
        payload = schemas.LoginUserSchema(email="nonexistent@example.com", password="password")

        response = self.client.post(f'{auth_route}/login', json=payload.dict())

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json() == {"detail": "Incorrect Email or Password"}

    def test_login_user_not_verified(self):
        populate_test_user(verified=False)
        payload = schemas.LoginUserSchema(email="tester@guy.com", password="password")

        response = self.client.post(f'{auth_route}/login', json=payload.dict())

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json() == {"detail": "Please verify your email address"}

    def test_login_incorrect_password(self):
        populate_test_user(password=hash_password('pass1234'))
        payload = schemas.LoginUserSchema(email="tester@guy.com", password="pass4567")

        response = self.client.post(f'{auth_route}/login', json=payload.dict())

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json() == {"detail": "Incorrect Email or Password"}

    @patch('app.db.check_user_exists')
    @patch('app.utils.verify_password')
    def test_login_successful(self, mock_check_user_exists, mock_verify_password):
        populate_test_user(password=hash_password('pass1234'))

        mock_verify_password.return_value = True
        payload = schemas.LoginUserSchema(email="tester@guy.com", password="pass1234")

        response = self.client.post(f'{auth_route}/login', json=payload.dict())
        assert response.status_code == status.HTTP_200_OK
        assert is_valid_token(response.json()["access_token"])
        cookies = response.cookies
        assert is_valid_token(cookies.get("refresh_token"))
        assert is_valid_token(cookies.get("access_token"))
        assert cookies.get("logged_in") == "True"


if __name__ == '__main__':
    unittest.main()
