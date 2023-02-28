import datetime
import calendar
from flask_restx import abort
import jwt

from constants import JWT_SECRET, JWT_ALGORITHM
from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_tokens(self, username: str, password: str, is_refresh=False) -> dict:
        user = self.user_service.get_by_username(username)

        if user is None:
            raise abort(404)

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                abort(400)

        data = {
            "username": user.username,
            "role": user.role
        }

        # 30 minutes for access_token
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

        # 130 days for refresh_token
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)

        tokens = {
            "access_token": access_token,
            "refresh_token": refresh_token
        }
        return tokens

    def approve_refresh_token(self, refresh_token: str) -> dict:
        data = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = data.get('username')

        user = self.user_service.get_by_username(username)

        if user is None:
            raise abort(404)

        return self.generate_tokens(username, user.password, is_refresh=True)
