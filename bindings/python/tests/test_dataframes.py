"""The pandas and Polars helpers (extras ``anonyma[pandas]``, ``anonyma[polars]``)."""

from __future__ import annotations

import pytest

from anonyma import Anonyma

ROWS = ["Mail ana@example.com", None, "No data", "Card 4111 1111 1111 1111"]


def test_pandas_anonymizes_a_column_and_keeps_the_rest() -> None:
    pd = pytest.importorskip("pandas")
    from anonyma.pandas import anonymize_series, detect_series

    engine = Anonyma(categories=["email", "credit-card"])
    series = pd.Series(ROWS + [float("nan"), 42], index=list("abcdef"), name="note")
    out = anonymize_series(series, engine)
    expected = [engine.anonymize(v) if isinstance(v, str) else v for v in series]
    assert out.index.tolist() == list("abcdef") and out.name == "note"
    assert out.tolist()[:4] == expected[:4] and out.iloc[5] == 42 and pd.isna(out.iloc[4])
    assert series.tolist()[0] == "Mail ana@example.com"  # the input is not changed

    found = detect_series(series, engine)
    assert [m.category for m in found["a"]] == ["email"]
    assert found["b"] is None and found["c"] == []
    assert anonymize_series(pd.Series([], dtype=object)).tolist() == []
    with pytest.raises(TypeError):
        anonymize_series(ROWS)  # type: ignore[arg-type]


def test_polars_anonymizes_a_column_and_an_expression() -> None:
    pl = pytest.importorskip("polars")
    from anonyma.polars import anonymize_expr, anonymize_series

    engine = Anonyma(categories=["email", "credit-card"])
    series = pl.Series("note", ROWS, dtype=pl.String)
    out = anonymize_series(series, engine)
    assert out.name == "note" and out.dtype == pl.String
    assert out.to_list() == [None if v is None else engine.anonymize(v) for v in ROWS]

    frame = pl.DataFrame({"note": ROWS, "id": [1, 2, 3, 4]})
    cleaned = frame.with_columns(anonymize_expr(pl.col("note"), engine))
    assert cleaned["note"].to_list() == out.to_list() and cleaned["id"].to_list() == [1, 2, 3, 4]
    with pytest.raises(TypeError):
        anonymize_series(pl.Series("n", [1, 2]))
