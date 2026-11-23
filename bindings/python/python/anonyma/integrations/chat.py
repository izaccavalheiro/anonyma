"""Shield and restore chat messages (OpenAI, Anthropic and compatible formats)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .. import Anonyma, Vault


def _shield_content(content: Any, anonyma: Anonyma, vault: Vault) -> Any:
    if isinstance(content, str):
        return anonyma.shield_prompt(content, vault).text
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, Mapping) and part.get("type") == "text" and isinstance(part.get("text"), str):
                part = {**part, "text": anonyma.shield_prompt(part["text"], vault).text}
            parts.append(part)
        return parts
    return content


def shield_messages(
    messages: Iterable[Mapping[str, Any]],
    anonyma: Anonyma,
    vault: Vault | None = None,
) -> tuple[list[dict[str, Any]], Vault]:
    """Copies of ``messages`` with personal data in their text replaced by vault tokens.

    String contents and ``{"type": "text"}`` parts are shielded; images, tool
    calls and other parts are passed through. The input is not modified.

    Returns:
        The shielded messages, and the vault to restore the answer with.
    """
    vault = Vault() if vault is None else vault
    shielded = [
        {**message, "content": _shield_content(message.get("content"), anonyma, vault)}
        for message in messages
    ]
    return shielded, vault


def restore_text(text: str, vault: Vault) -> str:
    """Put the original values back into a model's answer."""
    return vault.restore(text)[0]
