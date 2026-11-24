"""pandas helpers: anonymize or scan a column of text in one batch call.

Install with ``pip install anonyma[pandas]``. The values are sent to
:meth:`anonyma.Anonyma.anonymize_batch` in one call, which releases the GIL
and spreads the rows over every core; rows that are not strings (``None``,
``NaN``, numbers) are left as they are.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import Anonyma, Match

if TYPE_CHECKING:
    import pandas as pd


def _strings(series: pd.Series) -> pd.Series:
    """Which rows hold a string."""
    import pandas as pd

    if not isinstance(series, pd.Series):
        raise TypeError(f"expected a pandas Series, got {type(series).__name__}")
    return series.map(lambda value: isinstance(value, str)).astype(bool)


def anonymize_series(series: pd.Series, engine: Anonyma | None = None) -> pd.Series:
    """A copy of ``series`` with every string anonymized, index and dtype kept.

    Args:
        series: A column of text; rows that are not strings stay as they are.
        engine: The engine to use (its presets, rules and categories);
            ``Anonyma()`` when ``None``.
    """
    mask = _strings(series)
    out = series.copy()
    texts: list[str] = series[mask].tolist()
    if texts:
        out.loc[mask] = (engine or Anonyma()).anonymize_batch(texts)
    return out


def detect_series(series: pd.Series, engine: Anonyma | None = None) -> pd.Series:
    """For each row, the list of :class:`~anonyma.Match` found (``None`` for a row
    that is not a string), with the index of ``series``."""
    import pandas as pd

    mask = _strings(series)
    found: list[Any] = [None] * len(series)
    texts: list[str] = series[mask].tolist()
    matches: list[list[Match]] = (engine or Anonyma()).detect_batch(texts) if texts else []
    positions = [i for i, is_text in enumerate(mask.tolist()) if is_text]
    for position, row in zip(positions, matches):
        found[position] = row
    return pd.Series(found, index=series.index, name=series.name, dtype=object)
