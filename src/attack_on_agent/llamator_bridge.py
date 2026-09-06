from typing import Any

from llamator.client.chat_client import ClientBase

from attack_on_agent.target import send_messages


class TargetClient(ClientBase):
    """LLAMATOR client for a target whose sessions are real, server-side state.

    Memory attacks mark a session break by handing the client an empty history — that is what a
    freshly constructed ChatSession looks like. Holding one session id would keep that break
    invisible to the target: it would answer from the same working memory, and content merely
    recalled inside one conversation would be indistinguishable from content that survived a
    boundary. So a new history starts a new target session, and every id used is kept for the
    caller to finalize and collect evidence for.
    """

    def __init__(self, config: dict[str, Any], user_id: str, session_id: str, description: str | None = None):
        self.config = config
        self.user_id = user_id
        self.base_session_id = session_id
        self.sessions: list[str] = []
        self.model_description = description

    def interact(self, history: list[dict[str, str]], messages: list[dict[str, Any]]) -> dict[str, str]:
        if not history:
            self.sessions.append(f"{self.base_session_id}-{len(self.sessions) + 1}")
        response = send_messages(self.config, self.user_id, history + messages, self.sessions[-1])
        return {"role": "assistant", "content": response}
