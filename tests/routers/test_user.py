import unittest

from bson import ObjectId
from starlette.testclient import TestClient

from app.db import Users
from app.main import app
from tests.routers.test_auth import populate_test_user
from tests.utils import populate_test_users, create_test_token, authenticated_request

users_route = 'api/users'


class TestGetUser(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.user_id = ObjectId('669e483158ceb6772d1a1e23')
        self.token = create_test_token("tester@guy.com")

        Users.delete_many({})

    @authenticated_request
    def test_get_user_success(self):
        # Populate a test user
        populate_test_user()

        response = self.client.get(
            f"{users_route}/{self.user_id}",
            headers={"Authorization": f"Bearer {self.token}"}
        )

        assert response.status_code == 200
        response_json = response.json()
        assert response_json["message"] == "success"
        assert response_json["data"]["id"] == "669e483158ceb6772d1a1e23"
        assert response_json["data"]["email"] == "tester@guy.com"

    def test_get_user_unauthorized(self):
        response = self.client.get(
            f"{users_route}/{self.user_id}",
            headers={"Authorization": f"Bearer invalid_token"}
        )
        assert response.status_code == 401
        assert response.json() == {"detail": "Could not validate credentials"}

    @authenticated_request
    def test_get_user_not_found(self):
        populate_test_user()
        response = self.client.get(
            f"{users_route}/669e483158ceb6772d1a1e20",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        assert response.status_code == 404
        assert response.json() == {"detail": "User 669e483158ceb6772d1a1e20 not found"}


class TestUpdateUser(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.user_id = ObjectId('669e483158ceb6772d1a1e23')
        self.token = create_test_token("tester@guy.com")

        Users.delete_many({})

    @authenticated_request
    def test_update_user_not_found(self):
        populate_test_user()
        payload = {"full_name": "New Name"}
        response = self.client.put(
            f"{users_route}/669e483158ceb6772d1a1e20",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"}
        )
        assert response.status_code == 404
        assert response.json() == {"detail": f"User 669e483158ceb6772d1a1e20 not found"}

    @authenticated_request
    def test_update_user_invalid_role(self):
        populate_test_user()
        payload = {"role": "user"}
        response = self.client.put(
            f"{users_route}/{self.user_id}",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"}
        )

        assert response.status_code == 403
        assert response.json() == {"detail": "Operation not allowed"}

    @authenticated_request
    def test_delete_user(self):
        populate_test_user()
        payload = {"email": ""}
        response = self.client.put(
            f"{users_route}/{self.user_id}",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"}
        )

        assert response.status_code == 200
        assert response.json() == {'message': 'User successfully deleted',
                                   'data': {'id': '669e483158ceb6772d1a1e23', 'email': 'tester@guy.com'}}

    @authenticated_request
    def test_update_user_success(self):
        populate_test_user()
        payload = {"full_name": "New Name"}
        response = self.client.put(
            f"{users_route}/{self.user_id}",
            json=payload,
            headers={"Authorization": f"Bearer {self.token}"}
        )

        assert response.status_code == 200
        assert response.json() == {
            "message": "User successfully updated",
            "data": {"id": "669e483158ceb6772d1a1e23",
                     "full_name": "New Name",
                     "email": "tester@guy.com",
                     "role": "user"}
        }


class TestFindUsers(unittest.TestCase):
    def setUp(self):
        populate_test_users()
        self.client = TestClient(app)

        Users.delete_many({})

    @authenticated_request
    def test_find_users_success(self):
        response = self.client.get(
            users_route,
            params={"full_name": "John Doe", "limit": 10}
        )

        assert response.status_code == 200
        assert response.json() == {'data': [
            {'id': '5f5b7b9f6d6f75d482c09e1a',
             'full_name': 'John Doe',
             'email': 'john@example.com',
             'role': 'user'}],
            'total': 1, 'skip': 0, 'limit': 10}

    @authenticated_request
    def test_find_users_no_filters(self):
        response = self.client.get(users_route)

        assert response.status_code == 200
        assert response.json() == {
            'data': [
                {'id': '5f5b7b9f6d6f75d482c09e1a', 'full_name': 'John Doe', 'email': 'john@example.com',
                 'role': 'user'},
                {'id': '5f5b7b9f6d6f75d482c09e1b', 'full_name': 'Jane Doe', 'email': 'jane@example.com',
                 'role': 'admin'}
            ],
            'total': 2,
            'skip': 0,
            'limit': 10
        }

    @authenticated_request
    def test_find_users_empty_results(self):
        response = self.client.get(users_route, params={"full_name": "Nonexistent"})

        assert response.status_code == 200
        assert response.json() == {
            "data": [],
            "total": 0,
            "skip": 0,
            "limit": 10
        }

    def test_find_users_unauthorized(self):
        response = self.client.get(
            users_route,
            params={"full_name": "John Doe", "limit": 10}
        )

        assert response.status_code == 401
        assert response.json() == {'detail': 'Not authenticated'}


if __name__ == '__main__':
    unittest.main()
