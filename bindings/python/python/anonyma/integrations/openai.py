"""Shielding for the OpenAI Python SDK, without importing it.

>>> from openai import OpenAI                                 # doctest: +SKIP
>>> create = shielded_chat_completions(OpenAI(), Anonyma(categories=["email"]))  # doctest: +SKIP
>>> response = create(model="gpt-4.1", messages=[{"role": "user", "content": "Mail ana@example.com"}])  # doctest: +SKIP

The model receives ``Mail {{EMAIL_1}}``; ``response.choices[i].message.content``
has the original values back.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .. import Anonyma, Vault
from .chat import shield_messages


def shielded_chat_completions(
    client: Any,
    anonyma: Anonyma,
    vault: Vault | None = None,
) -> Callable[..., Any]:
    """A ``chat.completions.create`` that shields the messages and restores the answer.

    One vault serves every call, so a conversation keeps its tokens across
    turns. Streaming responses are not restored: pass ``stream=False``.
    """
    conversation = Vault() if vault is None else vault

    def create(**kwargs: Any) -> Any:
        if kwargs.get("stream"):
            raise ValueError("shielded_chat_completions does not restore streamed responses")
        messages, _ = shield_messages(kwargs.pop("messages", []), anonyma, conversation)
        response = client.chat.completions.create(messages=messages, **kwargs)
        for choice in getattr(response, "choices", []):
            message = getattr(choice, "message", None)
            content = getattr(message, "content", None)
            if isinstance(content, str):
                message.content = conversation.restore(content)[0]
        return response

    return create
