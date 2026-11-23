"""The Pythonic API: what the conformance suite does not cover."""

from __future__ import annotations

import threading

import pytest

import anonyma
from anonyma import Anonyma, AnonymaError, UnsupportedCategoriesError, Vault


def test_presets_refuse_categories_the_core_does_not_detect() -> None:
    with pytest.raises(UnsupportedCategoriesError) as raised:
        Anonyma(presets=["ccpa"])
    assert "api-key" in str(raised.value)
    assert Anonyma(presets=["ccpa"], allow_partial=True).undetected == ("api-key",)


def test_lgpd_and_hipaa_are_served_in_full() -> None:
    engine = Anonyma(presets=["lgpd", "hipaa"])
    assert engine.undetected == ()
    assert engine.anonymize("CPF 529.982.247-25, card 4111111111111111.") == (
        "CPF [REDACTED], card [REDACTED]."
    )


def test_pci_dss_is_served_in_full() -> None:
    engine = Anonyma("pci-dss")
    assert engine.undetected == ()
    assert engine.anonymize("Dear Ana Lima, card 4111111111111111") == (
        "Dear [REDACTED], card ************1111"
    )


def test_a_preset_name_alone() -> None:
    assert Anonyma("pci-dss", allow_partial=True).anonymize("Card 4111111111111111") == (
        "Card ************1111"
    )


def test_shield_prompt_and_restore_across_turns() -> None:
    engine = Anonyma(categories=["email", "credit-card"])
    first = engine.shield_prompt("Mail ana@example.com about 4111 1111 1111 1111.")
    assert first.text == "Mail {{EMAIL_1}} about {{CREDIT_CARD_1}}."
    assert first.tokens == (("{{EMAIL_1}}", "email"), ("{{CREDIT_CARD_1}}", "credit-card"))
    second = engine.shield_prompt("And bob@example.com, cc ana@example.com", first.vault)
    assert second.text == "And {{EMAIL_2}}, cc {{EMAIL_1}}"
    answer = "Sent to {{EMAIL_1}} and {{EMAIL_2}}; {{EMAIL_3}} is unknown."
    assert engine.restore(answer, second.vault) == (
        "Sent to ana@example.com and bob@example.com; {{EMAIL_3}} is unknown."
    )
    report = anonyma.restore(answer, second.vault)
    assert report.restored == 2
    assert report.unresolved == ("{{EMAIL_3}}",)


def test_offsets_are_code_points() -> None:
    text = "\N{E-MAIL SYMBOL} José: jose@example.com"
    [match] = Anonyma(categories=["email"]).detect(text)
    assert text[match.start : match.end] == "jose@example.com"


def test_rules_and_strategies() -> None:
    engine = Anonyma(
        rules={
            "credit-card": {"strategy": "mask", "keepTrailing": 4},
            "email": "redact",
            "ssn": {"strategy": "pseudonymize", "seed": "s3cr3t"},
        }
    )
    out = engine.anonymize_with_matches("Card 4111111111111111, ana@example.com, 123-45-6789")
    assert out.text.startswith("Card ************1111, [REDACTED], id_")
    assert out.counts == {"credit-card": 1, "email": 1, "ssn": 1}
    with pytest.raises(AnonymaError):
        Anonyma(rules={"email": "encrypt"})
    with pytest.raises(AnonymaError):
        Anonyma(categories=["e-mail"])


def test_vault_never_shows_its_values() -> None:
    vault = Vault([("{{EMAIL_1}}", "ana@example.com")])
    assert "ana" not in repr(vault)
    assert len(vault) == 1 and "{{EMAIL_1}}" in vault
    assert vault.delete("{{EMAIL_1}}") and len(vault) == 0


def test_validators_and_receipts() -> None:
    assert anonyma.validate("cpf", "529.982.247-25")
    assert not anonyma.validate("iban", "GB82 WEST 1234 5698 7654 33")
    assert "pix" in anonyma.validators()
    with pytest.raises(AnonymaError):
        anonyma.validate("nope", "1")
    issuer = anonyma.ReceiptIssuer("k", presets=["lgpd"], key_id="2026-11")
    receipt = issuer.issue("Mail [REDACTED]", {"email": 1}, input="Mail ana@example.com")
    assert receipt["keyId"] == "2026-11"
    assert receipt["library"].startswith("anonyma-python@")
    assert issuer.verify(receipt, output="Mail [REDACTED]", input="Mail ana@example.com") == (True, None)
    assert issuer.verify({**receipt, "total": 2}) == (False, "signature")
    assert anonyma.ReceiptIssuer("other").verify(receipt) == (False, "signature")


def test_engines_are_shared_between_threads() -> None:
    engine = Anonyma(categories=["email"])
    results: list[str] = []

    def work() -> None:
        results.append(engine.anonymize("Mail ana@example.com"))

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == ["Mail [REDACTED]"] * 8
