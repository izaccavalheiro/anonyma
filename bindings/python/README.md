# anonyma for Python

PII detection and anonymization on a Rust core, with no runtime dependencies,
no models to download and no cold start. It shields prompts before they reach
an LLM and restores the answers.

```python
from anonyma import Anonyma

engine = Anonyma(categories=["email", "credit-card", "iban"])
shielded = engine.shield_prompt("Mail ana@example.com about card 4111 1111 1111 1111.")
shielded.text   # 'Mail {{EMAIL_1}} about card {{CREDIT_CARD_1}}.'

answer = call_your_model(shielded.text)            # the model never sees the values
engine.restore(answer, shielded.vault)             # values back in the answer
```

- **Detectors with checksums.** Card numbers pass Luhn, IBANs MOD-97, CPF and
  CNPJ their check digits, PIX payloads their CRC, so a well-formed number with
  a wrong check digit is not reported.
- **Reversible tokens.** `{{EMAIL_1}}`, `{{CREDIT_CARD_1}}` keep a prompt
  readable for the model. One vault per conversation keeps the numbering across
  turns, and `{{PERSON_1}}` is never mistaken for part of `{{PERSON_10}}`.
- **Compliance presets.** `Anonyma(presets=["lgpd", "hipaa"])` combines
  presets; each category gets the most protective strategy.
- **Signed receipts.** `ReceiptIssuer(key).issue(output, counts)` records what
  was replaced, without the data, signed with HMAC-SHA-256.
- **The same results as the TypeScript package.** Both run the same conformance
  suite.

## Status: alpha

The Rust core detects 24 of the 27 categories of the TypeScript package, and
serves every compliance preset but CCPA in full: `Anonyma(presets=["lgpd",
"hipaa"])` works as is. A category it cannot detect yet (API keys, tracking
numbers, case numbers) raises `UnsupportedCategoriesError` and names what is
missing, instead of silently letting the data through:

```python
Anonyma(presets=["ccpa"])                      # UnsupportedCategoriesError: api-key
engine = Anonyma(presets=["ccpa"], allow_partial=True)
engine.undetected                              # ('api-key',)
```

`anonyma.capabilities()` lists what the core passes in the conformance suite.
If you need every category from Python today, run the sidecar
(`packages/sidecar`) and call it over HTTP.

## Integrations

| Module                          | For                                                                  |
| ------------------------------- | -------------------------------------------------------------------- |
| `anonyma.integrations.chat`     | message lists in OpenAI and Anthropic formats: `shield_messages()`   |
| `anonyma.integrations.openai`   | `shielded_chat_completions(client, engine)` wraps `chat.completions.create` |
| `anonyma.integrations.langchain`| `shield_and_restore(engine)`: two runnables for an LCEL chain (`pip install 'anonyma[langchain]'`) |

## Building from source

```sh
pip install ./bindings/python[test]     # builds the wheel with maturin; needs a Rust toolchain
pytest bindings/python/tests            # includes the conformance suite
```

Offsets in `Match` are code points: `text[m.start:m.end] == m.value`.
