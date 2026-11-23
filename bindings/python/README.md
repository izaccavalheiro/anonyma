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

## Install

```sh
pip install --pre anonyma                 # a pre-release: pip needs --pre
pip install --pre 'anonyma[langchain]'    # with the LangChain integration
```

Wheels for Linux (x86_64, aarch64), macOS (x86_64, arm64) and Windows (x64),
for every Python from 3.10; no Rust toolchain needed.

## Status: alpha

The Rust core detects all 27 categories of the TypeScript package, with every
checksum validator, and serves every compliance preset in full:
`Anonyma(presets=["lgpd", "hipaa"])` works as is. It passes the whole
conformance suite. The API may still change before 1.0.

`anonyma.capabilities()` lists what the core passes in the conformance suite.

## Integrations

| Module                           | For                                                                                                      |
| -------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `anonyma.integrations.chat`      | message lists in OpenAI and Anthropic formats: `shield_messages()`                                       |
| `anonyma.integrations.openai`    | `shielded_chat_completions(client, engine)` wraps `chat.completions.create`                              |
| `anonyma.integrations.langchain` | `shield_and_restore(engine)`: two runnables for an LCEL chain (`pip install --pre 'anonyma[langchain]'`) |

## Building from source

```sh
pip install ./bindings/python[test]     # builds the wheel with maturin; needs a Rust toolchain
pytest bindings/python/tests            # includes the conformance suite
```

Offsets in `Match` are code points: `text[m.start:m.end] == m.value`.
