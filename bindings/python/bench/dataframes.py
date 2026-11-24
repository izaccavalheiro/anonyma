"""Time the pandas helper against a ready list and against one call per row.

    python bindings/python/bench/dataframes.py [rows]

Every value is synthetic.
"""

from __future__ import annotations

import sys
import time

import pandas as pd

from anonyma import Anonyma
from anonyma.pandas import anonymize_series


def best(run) -> float:
    run()
    times = []
    for _ in range(5):
        start = time.perf_counter()
        run()
        times.append(time.perf_counter() - start)
    return min(times)


def main() -> None:
    rows = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    texts = [
        f"2026-11-24 INFO request {i} served for user{i}@example.com in {i % 90} ms, card 4111 1111 1111 1111"
        for i in range(rows)
    ]
    series = pd.Series(texts)
    engine = Anonyma()
    for name, run in [
        ("Series.map(engine.anonymize), one call per row", lambda: series.map(engine.anonymize)),
        ("engine.anonymize_batch(list)", lambda: engine.anonymize_batch(texts)),
        ("anonymize_series(series)", lambda: anonymize_series(series, engine)),
    ]:
        seconds = best(run)
        print(f"{name:<50} {seconds * 1e6 / rows:8.2f} us/row")


if __name__ == "__main__":
    main()
