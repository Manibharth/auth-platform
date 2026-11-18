"""Measure Argon2id cost on THIS machine; pick parameters landing at 50-100 ms.

Run on the deployed instance size (e.g. as a one-off Cloud Run job), not a laptop.
    python scripts/tune_argon2.py
"""

from __future__ import annotations

import statistics
import time

from argon2 import PasswordHasher, Type

CANDIDATES = [(2, 19456), (3, 19456), (2, 32768), (3, 32768), (2, 65536), (3, 65536), (4, 65536)]


def measure(t: int, m: int, runs: int = 7) -> float:
    ph = PasswordHasher(time_cost=t, memory_cost=m, parallelism=1, type=Type.ID)
    ph.hash("warm-up-password")
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        ph.hash("correct-Horse-battery-42")
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def main() -> None:
    print(f"{'time_cost':>9} {'memory_KiB':>10} {'median_ms':>9}")
    best = None
    for t, m in CANDIDATES:
        ms = measure(t, m)
        flag = ""
        if 50 <= ms <= 100 and best is None:
            best = (t, m)
            flag = "  <- first in 50-100 ms band"
        print(f"{t:>9} {m:>10} {ms:>9.1f}{flag}")
    if best:
        print(f"\nSet ARGON2_TIME_COST={best[0]} ARGON2_MEMORY_COST_KIB={best[1]}")


if __name__ == "__main__":
    main()
