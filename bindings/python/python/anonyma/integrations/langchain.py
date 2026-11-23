"""Runnables for LangChain Expression Language chains (needs ``langchain-core``).

>>> shield, restore = shield_and_restore(Anonyma(categories=["email"]))  # doctest: +SKIP
>>> chain = shield | prompt | model | StrOutputParser() | restore         # doctest: +SKIP

``shield`` takes a string, or a dict whose string values are shielded; the
model only sees tokens; ``restore`` puts the values back in the final string.
Use one pair per conversation: its vault holds the original values.
"""

from __future__ import annotations

from typing import Any

from .. import Anonyma, Vault

try:
    from langchain_core.runnables import RunnableLambda
except ImportError as error:  # pragma: no cover - exercised without langchain-core
    raise ImportError(
        "anonyma.integrations.langchain needs langchain-core: pip install 'anonyma[langchain]'"
    ) from error


def shield_and_restore(
    anonyma: Anonyma,
    vault: Vault | None = None,
) -> tuple[RunnableLambda, RunnableLambda]:
    """A runnable that shields its input and one that restores its output."""
    conversation = Vault() if vault is None else vault

    def shield(value: Any) -> Any:
        if isinstance(value, str):
            return anonyma.shield_prompt(value, conversation).text
        if isinstance(value, dict):
            return {
                key: anonyma.shield_prompt(item, conversation).text if isinstance(item, str) else item
                for key, item in value.items()
            }
        return value

    def restore(value: Any) -> Any:
        return conversation.restore(value)[0] if isinstance(value, str) else value

    return RunnableLambda(shield, name="anonyma_shield"), RunnableLambda(restore, name="anonyma_restore")
