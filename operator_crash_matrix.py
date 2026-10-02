"""Deterministic OS-process race helper for operator crash recovery tests."""

from __future__ import annotations

from collections.abc import Callable
import multiprocessing
import os
from queue import Empty
from typing import Any

import pytest


RecoveryCall = Callable[[], tuple[dict[str, Any], int]]


def race_same_ticket_recovery(
    recover: RecoveryCall,
    *,
    process_count: int = 2,
    timeout_seconds: float = 15.0,
) -> list[dict[str, Any]]:
    """Race fresh OS processes over one already-claimed effect ticket.

    Operator crash tests call this only after one verified inner effect exists and
    before any outer completion exists. Every child receives the same recovery
    callback through ``fork``. The helper proves no child dispatches the effect
    again; class-specific tests prove one durable recovered completion and one
    provider/filesystem/network mutation.
    """

    if process_count != 2:
        raise ValueError(
            "operator crash matrix requires exactly two recovery processes"
        )
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("operator crash matrix requires POSIX fork isolation")

    context = multiprocessing.get_context("fork")
    start = context.Barrier(process_count + 1)
    results = context.Queue()

    def worker() -> None:
        try:
            start.wait(timeout=timeout_seconds)
            result, downstream_calls = recover()
            results.put(
                {
                    "pid": os.getpid(),
                    "result": result,
                    "downstream_calls": downstream_calls,
                }
            )
        except BaseException as error:  # noqa: BLE001 - child must report every failure
            results.put(
                {
                    "pid": os.getpid(),
                    "error_type": type(error).__name__,
                    "error": str(error)[:500],
                }
            )

    processes = [context.Process(target=worker) for _ in range(process_count)]
    for process in processes:
        process.start()

    try:
        start.wait(timeout=timeout_seconds)
        rows: list[dict[str, Any]] = []
        for _ in processes:
            try:
                row = results.get(timeout=timeout_seconds)
            except Empty as error:
                raise AssertionError(
                    "operator recovery process returned no result"
                ) from error
            assert isinstance(row, dict)
            rows.append(row)
    finally:
        for process in processes:
            process.join(timeout=timeout_seconds)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        results.close()
        results.join_thread()

    assert all(process.exitcode == 0 for process in processes), [
        process.exitcode for process in processes
    ]
    assert len({row["pid"] for row in rows}) == process_count
    assert os.getpid() not in {row["pid"] for row in rows}
    assert all("error_type" not in row for row in rows), rows
    assert all(row["downstream_calls"] == 0 for row in rows), rows
    recovered = [row["result"] for row in rows]
    assert all(
        isinstance(result, dict) and result.get("success") is True
        for result in recovered
    ), recovered
    return recovered
