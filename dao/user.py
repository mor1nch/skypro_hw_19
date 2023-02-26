from dao.model.user import User


class UserDAO:
    def __init__(self, session):
        self.session = session

    def get_one(self, uid):
        return self.session.query(User).get(uid)

    def get_all(self):
        return self.session.query(User).all()

    def create(self, data):
        ent = User(**data)
        self.session.add(ent)
        self.session.commit()
        return ent

    def delete(self, uid):
        user = self.get_one(uid)
        self.session.delete(user)
        self.session.commit()

    def update(self, user_id):
        user = self.get_one(user_id.get("id"))
        user.username = user_id.get("username")
        user.password = user_id.get("password")
        user.role = user_id.get("role")

        self.session.add(user)
        self.session.commit()
