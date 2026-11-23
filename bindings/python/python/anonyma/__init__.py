"""anonyma: PII detection and anonymization on a Rust core.

>>> from anonyma import Anonyma
>>> engine = Anonyma(categories=["email", "credit-card"])
>>> shielded = engine.shield_prompt("Mail ana@example.com about card 4111 1111 1111 1111.")
>>> shielded.text
'Mail {{EMAIL_1}} about card {{CREDIT_CARD_1}}.'
>>> engine.restore("Done: wrote to {{EMAIL_1}}.", shielded.vault)
'Done: wrote to ana@example.com.'

The detectors, checksums, token formats and receipts are those of the
TypeScript package ``anonyma``, implemented once in Rust (``anonyma-core``)
and checked against the same conformance suite. Offsets are code points, as
Python indexes strings.

A category the Rust core does not detect in full yet is refused, never
silently skipped: ``Anonyma(presets=["lgpd"])`` raises
:class:`UnsupportedCategoriesError` and names the categories, until you pass
``allow_partial=True`` or the core ports them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Union

from . import _native
from ._native import AnonymaError, UnsupportedCategoriesError, Vault

try:
    __version__ = version("anonyma")
except PackageNotFoundError:  # pragma: no cover - a source checkout without metadata
    __version__ = _native.__version__

__all__ = [
    "Anonyma",
    "AnonymaError",
    "Anonymized",
    "Match",
    "ReceiptIssuer",
    "Restored",
    "Shielded",
    "UnsupportedCategoriesError",
    "Vault",
    "canonicalize",
    "capabilities",
    "detokenize",
    "preset",
    "restore",
    "scan",
    "sha256_hex",
    "Span",
    "validate",
    "validators",
]

#: A strategy: ``"redact"``, or a mapping as anonyma spells it,
#: ``{"strategy": "mask", "keepTrailing": 4}``.
Strategy = Union[str, Mapping[str, Any]]


def _call(op: str, payload: Mapping[str, Any]) -> Any:
    """Call the JSON API of the core and unwrap its answer."""
    answer = json.loads(_native.call(op, json.dumps(payload, ensure_ascii=False)))
    if "error" in answer:
        raise AnonymaError(answer["error"])
    return answer["ok"]


def _strategy_json(strategy: Strategy) -> str:
    spec = {"strategy": strategy} if isinstance(strategy, str) else dict(strategy)
    return json.dumps(spec)


def _names(value: str | Iterable[str] | None) -> list[str] | None:
    if value is None:
        return None
    return [value] if isinstance(value, str) else list(value)


@dataclass(frozen=True)
class Match:
    """A value of personal data found in a text. Offsets are code points."""

    category: str
    value: str
    start: int
    end: int
    confidence: float


@dataclass(frozen=True)
class Anonymized:
    """An anonymized text and what was replaced in it."""

    text: str
    matches: tuple[Match, ...]

    @property
    def counts(self) -> dict[str, int]:
        """How many values of each category were replaced, for a receipt."""
        counts: dict[str, int] = {}
        for match in self.matches:
            counts[match.category] = counts.get(match.category, 0) + 1
        return counts


@dataclass(frozen=True)
class Shielded:
    """A prompt with its personal data replaced by vault tokens."""

    text: str
    vault: Vault
    #: Each token placed, in document order, with its category.
    tokens: tuple[tuple[str, str], ...] = field(default=())


@dataclass(frozen=True)
class Restored:
    """A text with its tokens restored."""

    text: str
    restored: int
    unresolved: tuple[str, ...]


class Anonyma:
    """Detects and anonymizes personal data.

    Args:
        presets: Compliance presets (``"lgpd"``, ``"gdpr"``, ``"hipaa"``, ...);
            several combine, each category taking the most protective strategy.
        categories: Detect these categories only.
        rules: A strategy per category, ``{"credit-card": {"strategy": "mask",
            "keepTrailing": 4}}``; ``"redact"`` is short for ``{"strategy": "redact"}``.
            Without presets, they are the categories detected; with presets, they
            override the presets' strategies and add the categories they name.
        default_strategy: The strategy of categories without a rule.
        aggressive: Use the aggressive detectors (obfuscated e-mail addresses,
            masked card numbers).
        strict: Verify check digits where the default detector does not (CPF).
        allow_partial: Accept categories the Rust core does not detect in full
            yet; :attr:`undetected` lists them.

    Raises:
        UnsupportedCategoriesError: A category is not detected in full and
            ``allow_partial`` is false.
        AnonymaError: An unknown preset, category or strategy.
    """

    def __init__(
        self,
        presets: str | Iterable[str] | None = None,
        *,
        categories: Iterable[str] | None = None,
        rules: Mapping[str, Strategy] | None = None,
        default_strategy: Strategy | None = None,
        aggressive: bool = False,
        strict: bool = False,
        allow_partial: bool = False,
    ) -> None:
        self._engine = _native.Engine(
            presets=_names(presets),
            categories=_names(categories),
            rules=[(category, _strategy_json(s)) for category, s in (rules or {}).items()],
            default_strategy=None if default_strategy is None else _strategy_json(default_strategy),
            aggressive=aggressive,
            strict=strict,
            allow_partial=allow_partial,
        )

    @property
    def undetected(self) -> tuple[str, ...]:
        """Categories asked for that the Rust core does not detect in full."""
        return tuple(self._engine.undetected())

    def detect(self, text: str) -> list[Match]:
        """Every value found, without overlaps, in document order."""
        return [Match(*found) for found in self._engine.detect(text)]

    def detect_batch(self, texts: Iterable[str]) -> list[list[Match]]:
        """:meth:`detect` on each text, in order, in one call: short texts are
        scanned together, which costs far less than a call each (log lines,
        rows, chat turns). The GIL is released during the call."""
        return [[Match(*found) for found in matches] for matches in self._engine.detect_batch(list(texts))]

    def anonymize_batch(self, texts: Iterable[str]) -> list[str]:
        """:meth:`anonymize` on each text, in order, in one call, as
        :meth:`detect_batch` does."""
        return self._engine.anonymize_batch(list(texts))

    def contains_pii(self, text: str) -> bool:
        """Whether ``text`` holds any value this engine detects."""
        return bool(self._engine.detect(text))

    def anonymize(self, text: str) -> str:
        """``text`` with every value replaced by its category's strategy."""
        return self._engine.anonymize(text)[0]

    def anonymize_with_matches(self, text: str) -> Anonymized:
        """:meth:`anonymize`, with what was replaced."""
        out, matches = self._engine.anonymize(text)
        return Anonymized(out, tuple(Match(*found) for found in matches))

    def tokenize(self, text: str) -> tuple[str, dict[str, str]]:
        """Classic tokens (``[EMAIL_0001]``) and the mapping back to the values."""
        out, mapping = self._engine.tokenize(text)
        return out, dict(mapping)

    def shield_prompt(self, text: str, vault: Vault | None = None) -> Shielded:
        """Replace personal data with vault tokens (``{{EMAIL_1}}``) before a
        prompt leaves for a model.

        Pass the vault of the conversation to keep numbering across turns: a
        value keeps its token, and tokens the vault already holds are never
        reused for another value.
        """
        vault = Vault() if vault is None else vault
        out, tokens = self._engine.shield(text, vault)
        return Shielded(out, vault, tuple(tokens))

    def restore(self, text: str, vault: Vault) -> str:
        """Put the original values back into a model's answer."""
        return vault.restore(text)[0]


@dataclass(frozen=True)
class Span:
    """A detection of :func:`scan`. Offsets are code points."""

    category: str
    detector: str
    value: str
    start: int
    end: int
    confidence: float
    #: True for the part of a detection a stronger overlapping one left uncovered.
    residual: bool


def scan(
    text: str,
    categories: Iterable[str] | None = None,
    *,
    detection: str = "precise",
    aggressive: bool = False,
    min_confidence: float = 0.0,
) -> list[Span]:
    """The span engine of anonyma: precise detectors, overlaps resolved by covering.

    It matches ``compilePipeline({ categories, detection, aggressive,
    minConfidence }).scan(text)`` of the TypeScript package.
    """
    payload: dict[str, Any] = {
        "text": text,
        "detection": detection,
        "aggressive": aggressive,
        "minConfidence": min_confidence,
    }
    names = _names(categories)
    if names is not None:
        payload["categories"] = names
    return [Span(**span) for span in _call("scan", payload)["spans"]]


def restore(text: str, vault: Vault) -> Restored:
    """Restore every token of ``text`` that ``vault`` holds, and report the others.

    Each token is matched whole, so ``{{PERSON_1}}`` never matches inside
    ``{{PERSON_10}}``, and a restored value is never restored again.
    """
    out, count, unresolved = vault.restore(text)
    return Restored(out, count, tuple(unresolved))


def detokenize(text: str, mapping: Mapping[str, str]) -> Restored:
    """Restore classic tokens with the mapping of :meth:`Anonyma.tokenize`."""
    out, count, unresolved = _native.detokenize(text, list(mapping.items()))
    return Restored(out, count, tuple(unresolved))


def validate(validator: str, value: str) -> bool:
    """Run a checksum validator: ``validate("cpf", "529.982.247-25")``."""
    return bool(_call("validate", {"validator": validator, "value": value})["valid"])


def validators() -> list[str]:
    """The names of the checksum validators."""
    return list(_call("validators", {})["validators"])


def capabilities() -> list[str]:
    """The conformance capabilities of the Rust core under this package."""
    return list(_call("capabilities", {})["capabilities"])


def preset(*names: str) -> dict[str, Any]:
    """The categories and strategies of presets, combined when several:
    ``preset("lgpd", "hipaa")``."""
    return dict(_call("preset", {"names": list(names)}))


def canonicalize(value: Any) -> str:
    """Canonical JSON: members sorted, no white space. Numbers must be integers."""
    return str(_call("canonicalize", {"value": value})["text"])


def sha256_hex(text: str) -> str:
    """SHA-256 of the UTF-8 encoding of ``text``, in lower-case hex."""
    return str(_call("digest", {"text": text})["hex"])


class ReceiptIssuer:
    """Issues and verifies signed anonymization receipts (HMAC-SHA-256).

    A receipt records how many values of each category were replaced and the
    SHA-256 of the output, never the data, and cannot be forged without the key.

    >>> issuer = ReceiptIssuer("a-secret-key", presets=["lgpd"])
    >>> receipt = issuer.issue("Mail [REDACTED]", {"email": 1})
    >>> issuer.verify(receipt, output="Mail [REDACTED]")
    (True, None)
    """

    def __init__(
        self,
        key: str,
        *,
        presets: Sequence[str] | None = None,
        key_id: str | None = None,
    ) -> None:
        if not key:
            raise AnonymaError("key must be a non-empty string")
        self._key = key
        self._presets = list(presets) if presets is not None else None
        self._key_id = key_id

    def __repr__(self) -> str:
        return f"ReceiptIssuer(key_id={self._key_id!r})"

    def issue(
        self,
        output: str,
        counts: Mapping[str, int],
        *,
        input: str | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        """A signed receipt for ``output`` (the anonymized text)."""
        payload: dict[str, Any] = {
            "key": self._key,
            "text": output,
            "counts": dict(counts),
            "library": f"anonyma-python@{__version__}",
        }
        if self._presets is not None:
            payload["presets"] = self._presets
        if self._key_id is not None:
            payload["keyId"] = self._key_id
        if input is not None:
            payload["input"] = input
        if timestamp is not None:
            payload["timestamp"] = timestamp
        return dict(_call("receipt.issue", payload)["receipt"])

    def sign(self, body: Mapping[str, Any]) -> str:
        """The signature of a receipt body."""
        return str(_call("receipt.sign", {"key": self._key, "body": dict(body)})["signature"])

    def verify(
        self,
        receipt: Mapping[str, Any],
        *,
        output: str | None = None,
        input: str | None = None,
    ) -> tuple[bool, str | None]:
        """``(True, None)``, or ``(False, reason)`` with reason ``"malformed"``,
        ``"signature"``, ``"output"`` or ``"input"``."""
        payload: dict[str, Any] = {"key": self._key, "receipt": dict(receipt)}
        if output is not None:
            payload["output"] = output
        if input is not None:
            payload["input"] = input
        result = _call("receipt.verify", payload)
        return bool(result["valid"]), result.get("reason")
