"""LLM integrations, with stand-ins for the SDKs."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from anonyma import Anonyma
from anonyma.integrations.chat import restore_text, shield_messages
from anonyma.integrations.openai import shielded_chat_completions

ENGINE = Anonyma(categories=["email"])


def test_shield_messages_copies_and_shields_text_only() -> None:
    messages = [
        {"role": "system", "content": "Be brief."},
        {"role": "user", "content": [
            {"type": "text", "text": "Mail ana@example.com"},
            {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}},
        ]},
    ]
    shielded, vault = shield_messages(messages, ENGINE)
    assert shielded[1]["content"][0]["text"] == "Mail {{EMAIL_1}}"
    assert shielded[1]["content"][1] == messages[1]["content"][1]
    assert messages[1]["content"][0]["text"] == "Mail ana@example.com"
    assert restore_text("To {{EMAIL_1}}", vault) == "To ana@example.com"


class FakeCompletions:
    def __init__(self) -> None:
        self.seen: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.seen.append(kwargs)
        message = SimpleNamespace(content=f"Echo: {kwargs['messages'][-1]['content']}")
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_openai_wrapper_shields_requests_and_restores_answers() -> None:
    completions = FakeCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    create = shielded_chat_completions(client, ENGINE)
    response = create(model="m", messages=[{"role": "user", "content": "Mail ana@example.com"}])
    assert completions.seen[0]["messages"][0]["content"] == "Mail {{EMAIL_1}}"
    assert completions.seen[0]["model"] == "m"
    assert response.choices[0].message.content == "Echo: Mail ana@example.com"
    with pytest.raises(ValueError):
        create(model="m", messages=[], stream=True)


def test_langchain_runnables() -> None:
    pytest.importorskip("langchain_core")
    from anonyma.integrations.langchain import shield_and_restore

    shield, restore = shield_and_restore(ENGINE)
    chain = shield | (lambda prompt: f"Answer about {prompt['question']}") | restore
    assert chain.invoke({"question": "ana@example.com"}) == "Answer about ana@example.com"
    assert shield.invoke("x ana@example.com") == "x {{EMAIL_1}}"
