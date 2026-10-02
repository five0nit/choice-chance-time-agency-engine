"""Coalesce display-only heartbeats; never cache reads used for authorization."""
from contextlib import nullcontext
from copy import deepcopy
import os
import re
import time

from .cloud_backoff import CloudCircuit

HEARTBEAT_SECONDS = 120
MAX_HEARTBEAT_SECONDS = 1800


def projection_heartbeat_seconds():
    """Host-only display cadence; invalid explicit configuration fails closed."""
    value = os.environ.get("CCT_CLOUD_PROJECTION_HEARTBEAT_SECONDS")
    if value is None:
        return HEARTBEAT_SECONDS
    if (not re.fullmatch(r"[0-9]{3,4}", value)
            or not HEARTBEAT_SECONDS <= int(value) <= MAX_HEARTBEAT_SECONDS):
        raise ValueError("CLOUD_PROJECTION_HEARTBEAT_INVALID")
    return int(value)

# Exact host-owned projection paths only. Do not ignore revisions in authority,
# request, answer, or queue documents. Discovery revision is a view sequence.
VOLATILE = {
    "cct_discovery": (("updatedAt",), ("revision",)),
    "cct_owner_runtime": (("updatedAt",),),
    "cct_executor_runtime": (("updatedAt",),),
    "cct_owner_work": (("updatedAt",),),
    "cct_owner_delivery": (("updatedAt",), ("continuation", "updatedAt")),
    # Build-control status publication is an existing pre-effect readback gate;
    # leave it uncached even though the document is also displayed.
    "cct_owner_build_library": (),
    "cct_owner_build_request_status": (),
    "cct_dashboard": (("publishedAt",), ("snapshotSha256",), ("snapshot", "generated_at"),
                      ("snapshot", "collaboration", "observedAt")),
    "cct_bridge_status": (("publishedAt",),),
}


class ProjectionCache:
    def __init__(self, *, clock=time.monotonic):
        self.clock, self.entries = clock, {}
        self.heartbeat_seconds = projection_heartbeat_seconds()

    def publish(self, collection, name, value, write, *, force=False, circuit=None):
        key = (collection, name)
        normalized = deepcopy(value)
        for path in VOLATILE.get(collection, ()):
            row = normalized
            for part in path[:-1]:
                row = row.get(part, {})
            row.pop(path[-1], None)
        guard = (circuit.display_cache_guard() if isinstance(circuit, CloudCircuit)
                 else nullcontext(True))
        with guard as cache_allowed:
            saved = self.entries.get(key)
            if (cache_allowed and not force and collection in VOLATILE and saved
                    and saved[0] == normalized
                    and 0 <= self.clock() - saved[1] < self.heartbeat_seconds):
                # Decide/copy under the project lock; a sibling cannot persist
                # backoff between validation and this cached-return decision.
                return deepcopy(saved[2])
        # Gateway RPCs acquire the same lock; never call them inside the guard.
        write()
        if collection in VOLATILE:
            if len(self.entries) >= 256 and key not in self.entries:
                self.entries.pop(next(iter(self.entries)))
            self.entries[key] = (normalized, self.clock(), deepcopy(value))
        return value


def publish_projection(gateway, collection, name, value):
    circuit = getattr(gateway, "circuit", None)
    cache = getattr(gateway, "_projection_cache", None)
    if not isinstance(cache, ProjectionCache):
        cache = gateway._projection_cache = ProjectionCache()

    def write():
        verified = gateway.publish(collection, name, value)
        # Production gateway already verifies exactly; injected/legacy gateways
        # must still prove readback before anything enters the projection cache.
        if verified != value and gateway.read(collection, name) != value:
            raise RuntimeError("CLOUD_PROJECTION_READBACK_MISMATCH")

    return cache.publish(collection, name, value, write, circuit=circuit)
