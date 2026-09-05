from typing import Any

from llamator.client.chat_client import ClientBase

from attack_on_agent.target import send_messages


class TargetClient(ClientBase):
    """LLAMATOR client that preserves the target user and session selected by an experiment."""

    def __init__(self, config: dict[str, Any], user_id: str, session_id: str):
        self.config = config
        self.user_id = user_id
        self.session_id = session_id

    def interact(self, history: list[dict[str, str]], messages: list[dict[str, Any]]) -> dict[str, str]:
        response = send_messages(self.config, self.user_id, history + messages, self.session_id)
        return {"role": "assistant", "content": response}
