"""The conformance suite (packages/conformance) through the public Python API.

Every case whose capabilities the core declares must pass; the others are
skipped, and reported by pytest with the capability they need.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import anonyma
from anonyma import Anonyma, ReceiptIssuer, Vault

SUITE_PATH = Path(__file__).resolve().parents[3] / "packages" / "conformance" / "conformance-tests.json"
SUITE = json.loads(SUITE_PATH.read_text(encoding="utf-8"))
PROVIDED = set(anonyma.capabilities())


def engine(data: dict[str, Any]) -> Anonyma:
    return Anonyma(
        categories=data["categories"],
        aggressive=data.get("aggressive", False),
        strict=data.get("strict", False),
        allow_partial=True,
    )


def run(op: str, data: dict[str, Any]) -> dict[str, Any]:
    if op == "validate":
        return {"valid": anonyma.validate(data["validator"], data["value"])}
    if op == "detect":
        return {"matches": [vars(m) for m in engine(data).detect(data["text"])]}
    if op == "scan":
        spans = anonyma.scan(
            data["text"],
            data["categories"],
            detection=data.get("detection", "precise"),
            aggressive=data.get("aggressive", False),
            min_confidence=data.get("minConfidence", 0.0),
        )
        return {"spans": [vars(span) for span in spans]}
    if op == "tokenize":
        text, mapping = engine(data).tokenize(data["text"])
        return {"text": text, "mapping": [list(pair) for pair in mapping.items()]}
    if op == "detokenize":
        out = anonyma.detokenize(data["text"], dict(data["mapping"]))
        return {"text": out.text, "replacedCount": out.restored, "unresolved": list(out.unresolved)}
    if op == "shield":
        vault = Vault([tuple(pair) for pair in data["vault"]])
        shielded = engine(data).shield_prompt(data["text"], vault)
        return {"text": shielded.text, "vault": [list(pair) for pair in vault.entries()]}
    if op == "restore":
        out = anonyma.restore(data["text"], Vault([tuple(pair) for pair in data["vault"]]))
        return {"text": out.text, "restored": out.restored, "unresolved": list(out.unresolved)}
    if op == "anonymize":
        rules = {rule["category"]: rule["strategy"] for rule in data.get("rules", [])}
        return {"text": Anonyma(data.get("preset"), rules=rules or None).anonymize(data["text"])}
    if op == "preset":
        return anonyma.preset(*data["names"])
    if op == "canonicalize":
        return {"text": anonyma.canonicalize(data["value"])}
    if op == "digest":
        return {"hex": anonyma.sha256_hex(data["text"])}
    if op == "receipt.sign":
        return {"signature": ReceiptIssuer(data["key"]).sign(data["body"])}
    if op == "receipt.verify":
        valid, reason = ReceiptIssuer(data["key"]).verify(data["receipt"])
        return {"valid": True} if valid else {"valid": False, "reason": reason}
    if op == "receipt.issue":
        issuer = ReceiptIssuer(data["key"], presets=data.get("presets"))
        receipt = issuer.issue(data["text"], data["counts"], timestamp=data["timestamp"])
        return {"receipt": receipt, "verified": issuer.verify(receipt)[0]}
    raise AssertionError(f"unknown operation {op}")


def compare(op: str, expected: dict[str, Any], actual: dict[str, Any]) -> None:
    if op in ("detect", "scan"):
        key = "spans" if op == "scan" else "matches"
        want, got = expected[key], actual[key]
        assert len(got) == len(want), got
        for w, g in zip(want, got):
            fields = [k for k in ("category", "detector", "value", "start", "end", "residual") if k in w]
            assert {k: g[k] for k in fields} == {k: w[k] for k in fields}
            assert g["confidence"] == pytest.approx(w["confidence"], abs=1e-9)
    elif op == "anonymize" and "textPattern" in expected:
        assert re.search(expected["textPattern"], actual["text"]), actual["text"]
    elif op == "receipt.issue":
        for key, value in expected["receipt"].items():
            assert actual["receipt"][key] == value, key
        assert actual["verified"] is True
    else:
        for key, value in expected.items():
            if key in ("mapping", "vault"):
                assert sorted(map(tuple, actual[key])) == sorted(map(tuple, value)), key
            else:
                assert actual[key] == value, key


@pytest.mark.parametrize("case", SUITE["cases"], ids=[case["id"] for case in SUITE["cases"]])
def test_case(case: dict[str, Any]) -> None:
    missing = [capability for capability in case["requires"] if capability not in PROVIDED]
    if missing:
        pytest.skip(f"needs {', '.join(missing)}")
    compare(case["op"], case["expected"], run(case["op"], case["input"]))


def test_most_cases_run() -> None:
    runnable = [c for c in SUITE["cases"] if all(r in PROVIDED for r in c["requires"])]
    assert len(runnable) >= 90
