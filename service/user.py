import base64
import hashlib
import hmac

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.user import UserDAO


class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid) -> list or None:
        return self.dao.get_one(uid)

    def get_all(self) -> list:
        return self.dao.get_all()

    def create(self, data: dict) -> list:
        return self.dao.create(data)

    def update(self, user_id: int) -> None:
        self.dao.update(user_id)

    def delete(self, uid: int) -> None:
        self.dao.delete(uid)

    def get_by_username(self, username: str):
        return self.dao.get_by_username(username)

    def get_hash(self, password: str):
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ).decode("utf-8", "ignore")

    def compare_passwords(self, password_hash, other_password: str) -> bool:
        decode_digest = base64.b64decode(password_hash)

        hash_digest = hashlib.pbkdf2_hmac(
            'sha256',
            other_password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )

        return hmac.compare_digest(decode_digest, hash_digest)
