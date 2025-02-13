import json
import jwt

from app.config import settings


def lambda_handler(event, context):
    token = event.get('authorizationToken', '')

    if not token:
        raise Exception('Unauthorized')

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        principal_id = payload['sub']

        auth_response = {
            'principalId': principal_id,
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [{
                    'Action': 'execute-api:Invoke',
                    'Effect': 'Allow',
                    'Resource': event['methodArn']
                }]
            },
            'context': {
                'user': json.dumps({
                    'email': payload['email'],
                    'role': payload.get('role', 'user')
                })
            }
        }
        return auth_response

    except jwt.ExpiredSignatureError:
        raise Exception('Unauthorized - Token Expired')
    except jwt.InvalidTokenError:
        raise Exception('Unauthorized - Invalid Token')
