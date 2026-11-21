---
title: FAQ
sidebar_position: 7
---

## Does anonyma send my data anywhere?

No. The library has no network, file-system or process code, and no runtime dependencies; CI checks
both on every change. The [playground](/playground) runs the same code in your
browser, and this site's Content Security Policy forbids it any connection.

## How accurate is detection?

It depends on the category. Formats with check digits (cards, IBANs, CPF, CNPJ, many national IDs)
are confirmed by the validating detectors, which leave look-alikes alone. Free-form data — names,
addresses — is found by patterns and context, and some will be missed; that is true of every
pattern-based tool. [Categories](reference/categories.md) says which is which. For names in free
text, consider an NER model in front of anonyma and pass its findings as a custom detector.

## Which strategy should I use?

Redact when nobody needs the value; mask when a human needs a hint (`****1111`); pseudonymize or
synthesize when the text must still read naturally; hash with a pepper when records must be joined
without the value; tokenize when the value must come back (an LLM round trip); encrypt when someone
authorised must recover it. See [Anonymization strategies](guide/strategies.md).

## Is pseudonymized data still personal data?

Under GDPR, usually yes: pseudonymised data that can be attributed with additional information stays
personal data (Recital 26). Keyed tokens and hashes reduce risk; they do not take data out of scope.
The [regulation profiles](reference/regulations.md) record what each regulation requires of a
strategy.

## Can I combine presets?

Yes: `preset: ["lgpd", "hipaa"]`. Each category gets the most protective strategy of the presets.
See [Several regulations at once](guides/several-regulations.md).

## Does it work with large files?

The [command line](packages/cli.md) streams text, CSV and JSON Lines in constant memory;
`createPipelineStream()` does the same in code.

## Is there a hosted version?

Not yet. Everything here runs where you run it.
