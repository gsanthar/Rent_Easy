# project/token.py

from itsdangerous import URLSafeTimedSerializer
from application import application


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer('my_precious')
    return serializer.dumps(email, salt= 'my_precious_two')


def cancel_token(token):
    serializer = URLSafeTimedSerializer('my_precious')
    try:
        email = serializer.loads(
            token,
            salt = 'my_precious_two'
        )
    except:
        return False
    return email

