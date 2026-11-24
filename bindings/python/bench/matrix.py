"""The Python binding's cells of the benchmark matrix (bench/matrix/).

    python bindings/python/bench/matrix.py <corpus dir> <out.jsonl>

Reads the corpus bench/matrix/corpus.mjs writes and writes the rows every
harness of the matrix writes, one JSON object per line.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

from anonyma import Anonyma


def median(run) -> float:
    """Median milliseconds of one run of ``run``, over at least 5 runs and 300 ms."""
    run()
    samples: list[float] = []
    start = time.perf_counter()
    while len(samples) < 5 or (time.perf_counter() - start < 0.3 and len(samples) < 50):
        t = time.perf_counter()
        run()
        samples.append((time.perf_counter() - t) * 1000)
    samples.sort()
    return samples[len(samples) // 2]


def main() -> None:
    corpus, out = Path(sys.argv[1]), Path(sys.argv[2])
    engine = Anonyma()
    rows = []

    def row(shape: str, entry_size: int, entries: int, threads: int, ms: float, matches: int) -> None:
        rows.append(
            {
                "engine": "python",
                "runtime": f"python {platform.python_version()}",
                "op": "detect",
                "shape": shape,
                "entrySize": entry_size,
                "entries": entries,
                "threads": threads,
                "medianMs": ms,
                "perEntryUs": ms * 1000 / entries,
                "matches": matches,
            }
        )
        print(json.dumps(rows[-1]))

    for name in ("1k", "100k", "1m"):
        text = (corpus / f"single-{name}.txt").read_text(encoding="utf-8")
        matches = len(engine.detect(text))
        row("single", len(text.encode()), 1, 1, median(lambda: engine.detect(text)), matches)

    entries = json.loads((corpus / "entries.json").read_text(encoding="utf-8"))
    size = sum(len(e.encode()) for e in entries) // len(entries)
    each = sum(len(engine.detect(e)) for e in entries)
    row("each", size, len(entries), 1, median(lambda: [engine.detect(e) for e in entries]), each)
    batch = sum(len(m) for m in engine.detect_batch(entries))
    # detect_batch runs on the core's rayon pool, one thread per core.
    row("batch", size, len(entries), os.cpu_count() or 1, median(lambda: engine.detect_batch(entries)), batch)

    out.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


if __name__ == "__main__":
    main()
