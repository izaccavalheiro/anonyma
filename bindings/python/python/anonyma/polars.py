"""Polars helpers: anonymize a column of text in one batch call.

Install with ``pip install anonyma[polars]``. The values are sent to
:meth:`anonyma.Anonyma.anonymize_batch` in one call, which releases the GIL
and spreads the rows over every core; null rows stay null.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from . import Anonyma

if TYPE_CHECKING:
    import polars as pl


def anonymize_series(series: pl.Series, engine: Anonyma | None = None) -> pl.Series:
    """A new String series with every value anonymized and nulls kept.

    Args:
        series: A ``String`` series.
        engine: The engine to use; ``Anonyma()`` when ``None``.
    """
    import polars as pl

    if not isinstance(series, pl.Series) or series.dtype != pl.String:
        raise TypeError("expected a polars Series of dtype String")
    values = series.to_list()
    positions = [i for i, value in enumerate(values) if value is not None]
    if positions:
        cleaned = (engine or Anonyma()).anonymize_batch([values[i] for i in positions])
        for position, text in zip(positions, cleaned):
            values[position] = text
    return pl.Series(series.name, values, dtype=pl.String)


def anonymize_expr(expr: pl.Expr, engine: Anonyma | None = None) -> pl.Expr:
    """An expression that anonymizes a String column, for ``select`` and
    ``with_columns``: ``df.with_columns(anonymize_expr(pl.col("note")))``."""
    import polars as pl

    return expr.map_batches(lambda series: anonymize_series(series, engine), return_dtype=pl.String)
