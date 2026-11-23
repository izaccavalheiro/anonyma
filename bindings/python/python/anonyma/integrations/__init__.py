"""Prompt shielding for LLM frameworks.

- :mod:`anonyma.integrations.chat`: chat message lists (OpenAI, Anthropic and
  compatible formats), no dependency.
- :mod:`anonyma.integrations.openai`: wraps ``client.chat.completions.create``
  of the OpenAI Python SDK, duck-typed (the SDK is not imported).
- :mod:`anonyma.integrations.langchain`: runnables for LangChain Expression
  Language chains (needs ``langchain-core``).
"""
