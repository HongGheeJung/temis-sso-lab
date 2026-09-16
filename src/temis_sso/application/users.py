from dataclasses import dataclass


@dataclass(frozen=True)
class UserProfile:
    user_id: str
    email: str


class UserDirectory:
    def __init__(self) -> None:
        self._users = {"learner-001": UserProfile("learner-001", "learner@lab.invalid")}

    def by_id(self, user_id: str) -> UserProfile | None:
        return self._users.get(user_id)
