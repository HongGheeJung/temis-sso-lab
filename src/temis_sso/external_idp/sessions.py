import secrets


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}

    def issue(self, user_id: str) -> str:
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = user_id
        return session_id

    def resolve(self, session_id: str) -> str | None:
        return self._sessions.get(session_id)

    def revoke(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
