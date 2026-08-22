"""Host-trusted team-sync event sensor for bounded continuity cycles.

This adapter treats provenance and content as separate concerns. A canonical
same-owner local JSONL file can establish trusted *producer authority*. Free
text is quarantined; only grammar-validated metadata and a digest enter CCT.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import grp
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import re
import stat
from typing import Any, Mapping
import unicodedata

from .cognitive_cycle import CognitiveCycle, Observation
from .kernel import AgencyKernel
from .models import Constitution
from .store import Event, EventStore, canonical_json


_CURSOR_KIND = "sensor.team_sync.cursor.advanced"
_REJECTION_KIND = "sensor.team_sync.item.rejected"
_RESET_KIND = "sensor.team_sync.source.reset"
_CONTINUITY_KIND = "sensor.team_sync.continuity"
_ALLOWED_SOURCE_NAME = "project_changes.jsonl"
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_CONTENT_POLICY = "metadata_only_v1"


@dataclass(frozen=True, slots=True)
class TeamSyncSensorPolicy:
    """Bounded source-reading and continuity policy."""

    max_events_per_run: int = 8
    max_scan_lines: int = 64
    max_scan_bytes: int = 262_144
    max_line_bytes: int = 16_384
    heartbeat_interval_seconds: int = 1_800
    start_at_end: bool = True
    projects: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "max_events_per_run",
            "max_scan_lines",
            "max_scan_bytes",
            "max_line_bytes",
            "heartbeat_interval_seconds",
        ):
            if int(getattr(self, name)) < 1:
                raise ValueError(f"{name} must be positive")
        if self.max_events_per_run > 8:
            raise ValueError("max_events_per_run cannot exceed workspace capacity 8")
        if self.max_scan_lines < self.max_events_per_run:
            raise ValueError("max_scan_lines cannot be below max_events_per_run")
        if self.max_line_bytes > self.max_scan_bytes:
            raise ValueError("max_line_bytes cannot exceed max_scan_bytes")
        normalized = tuple(
            sorted(
                {
                    str(project).strip()
                    for project in self.projects
                    if str(project).strip()
                }
            )
        )
        if len(normalized) > 100 or any(len(project) > 120 for project in normalized):
            raise ValueError("projects must contain at most 100 names of at most 120 characters")
        object.__setattr__(self, "projects", normalized)


@dataclass(frozen=True, slots=True)
class _SourceFrame:
    offset_before: int
    offset_after: int
    raw: bytes
    complete: bool
    oversized_segment: bool


class TeamSyncSensor:
    """Convert new canonical team-sync records into trusted CCT observations."""

    KIND_POLICY: Mapping[str, tuple[str, dict[str, float]]] = {
        "blocker": (
            "blocker",
            {
                "salience": 0.98,
                "goal_relevance": 0.98,
                "novelty": 0.85,
                "urgency": 0.98,
                "unresolved_conflict": 0.95,
            },
        ),
        "decision": (
            "decision_update",
            {
                "salience": 0.9,
                "goal_relevance": 0.95,
                "novelty": 0.8,
                "urgency": 0.75,
                "unresolved_conflict": 0.7,
            },
        ),
        "change": (
            "goal_progress",
            {
                "salience": 0.85,
                "goal_relevance": 0.95,
                "novelty": 0.85,
                "urgency": 0.8,
                "unresolved_conflict": 0.25,
            },
        ),
        "test": (
            "test_result",
            {
                "salience": 0.75,
                "goal_relevance": 0.75,
                "novelty": 0.7,
                "urgency": 0.6,
                "unresolved_conflict": 0.2,
            },
        ),
        "status": (
            "goal_progress",
            {
                "salience": 0.55,
                "goal_relevance": 0.55,
                "novelty": 0.4,
                "urgency": 0.2,
                "unresolved_conflict": 0.1,
            },
        ),
        "risk": (
            "risk",
            {
                "salience": 0.95,
                "goal_relevance": 0.95,
                "novelty": 0.8,
                "urgency": 0.9,
                "unresolved_conflict": 0.9,
            },
        ),
        "opportunity": (
            "opportunity",
            {
                "salience": 0.85,
                "goal_relevance": 0.9,
                "novelty": 0.95,
                "urgency": 0.7,
                "unresolved_conflict": 0.2,
            },
        ),
    }

    def __init__(
        self,
        store: EventStore,
        constitution: Constitution,
        source_path: str | Path,
        *,
        policy: TeamSyncSensorPolicy | None = None,
        source_id: str = "project_changes",
        trusted_root: str | Path | None = None,
    ) -> None:
        self.store = store
        self.constitution = constitution
        self.source_path = Path(source_path)
        self.policy = policy or TeamSyncSensorPolicy()
        self.source_id = self._text(source_id, name="source_id", maximum=80)
        self.trusted_root = (
            Path(trusted_root) if trusted_root is not None else self.source_path.parent
        )
        self._source_path_digest = sha256(
            str(self.source_path.absolute()).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _text(value: object, *, name: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        normalized = "".join(
            " " if unicodedata.category(character) in {"Cc", "Cf"} else character
            for character in value
        ).strip()
        normalized = " ".join(normalized.split())
        if not normalized:
            raise ValueError(f"{name} must not be empty")
        if len(normalized) > maximum:
            raise ValueError(f"{name} exceeds {maximum} characters")
        return normalized

    @staticmethod
    def _identifier(value: object, *, name: str, maximum: int) -> str:
        if not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
        if not value or len(value) > maximum or _IDENTIFIER_RE.fullmatch(value) is None:
            raise ValueError(
                f"{name} must be 1-{maximum} ASCII letters, digits, dots, underscores, or hyphens"
            )
        return value

    @staticmethod
    def _parse_time(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("team-sync timestamp must include a timezone")
        return parsed.astimezone(UTC)

    @staticmethod
    def _group_is_uid_exclusive(group_id: int, current_uid: int) -> bool:
        """Return true only when no other local UID resolves into the group."""

        try:
            group = grp.getgrgid(group_id)
            explicit_names = set(group.gr_mem)
            member_uids = {
                account.pw_uid
                for account in pwd.getpwall()
                if account.pw_gid == group_id or account.pw_name in explicit_names
            }
        except (KeyError, OSError):
            return False
        return member_uids <= {current_uid}

    @staticmethod
    def _assert_no_posix_acl(path: Path, *, label: str) -> None:
        try:
            attributes = set(os.listxattr(path, follow_symlinks=False))
        except OSError as exc:
            raise ValueError(f"unable to verify team-sync {label} ACLs") from exc
        if attributes & {"system.posix_acl_access", "system.posix_acl_default"}:
            raise ValueError(f"team-sync {label} must not have an extended POSIX ACL")

    def _validate_source(self) -> os.stat_result:
        if self.source_path.name != _ALLOWED_SOURCE_NAME:
            raise ValueError("team-sync source filename is not allowlisted")
        if self.source_path.is_symlink():
            raise ValueError("team-sync source must not be a symlink")
        if self.trusted_root.is_symlink():
            raise ValueError("team-sync trusted root must not be a symlink")
        source_resolved = self.source_path.resolve(strict=True)
        root_resolved = self.trusted_root.resolve(strict=True)
        if source_resolved.parent != root_resolved:
            raise ValueError("team-sync source escaped the trusted root")
        self._assert_no_posix_acl(self.source_path, label="source")
        self._assert_no_posix_acl(self.trusted_root, label="root")

        source_stat = self.source_path.stat()
        root_stat = self.trusted_root.stat()
        if not stat.S_ISREG(source_stat.st_mode):
            raise ValueError("team-sync source must be a regular file")
        if source_stat.st_nlink != 1:
            raise ValueError("team-sync source must not be hardlinked")
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("team-sync trusted root must be a directory")
        current_uid = os.getuid()
        if source_stat.st_uid != current_uid or root_stat.st_uid != current_uid:
            raise ValueError("team-sync source and root must be owned by the sensor uid")
        if source_stat.st_mode & stat.S_IWOTH or root_stat.st_mode & stat.S_IWOTH:
            raise ValueError("team-sync source and root must not be world writable")
        for label, metadata in (("source", source_stat), ("root", root_stat)):
            if not metadata.st_mode & stat.S_IWGRP:
                continue
            if metadata.st_gid != os.getgid() or not self._group_is_uid_exclusive(
                metadata.st_gid, current_uid
            ):
                raise ValueError(
                    f"group-writable team-sync {label} must use a UID-exclusive sensor group"
                )
        return source_stat

    def _cursor(self) -> Event | None:
        for event in reversed(self.store.events(_CURSOR_KIND)):
            payload = event.payload
            if (
                payload.get("source_id") == self.source_id
                and payload.get("source_path_sha256") == self._source_path_digest
            ):
                return event
        return None

    def _last_continuity_at(self) -> datetime | None:
        for event in reversed(self.store.events(_CONTINUITY_KIND)):
            if (
                event.payload.get("source_id") != self.source_id
                or event.payload.get("source_path_sha256")
                != self._source_path_digest
            ):
                continue
            value = event.payload.get("observed_at")
            if isinstance(value, str):
                try:
                    return self._parse_time(value)
                except ValueError:
                    return None
        return None

    def _append_cursor(
        self,
        *,
        source_stat: os.stat_result,
        offset: int,
        observed_at: datetime,
        primed: bool,
        scanned_lines: int,
        accepted_events: int,
        rejected_events: int,
        cycle_tick: int | None,
    ) -> Event:
        payload = {
            "source_id": self.source_id,
            "source_path_sha256": self._source_path_digest,
            "device": int(source_stat.st_dev),
            "inode": int(source_stat.st_ino),
            "offset": int(offset),
            "observed_at": observed_at.astimezone(UTC).isoformat(),
            "primed": bool(primed),
            "scanned_lines": int(scanned_lines),
            "accepted_events": int(accepted_events),
            "rejected_events": int(rejected_events),
            "cycle_tick": cycle_tick,
            "content_policy": _CONTENT_POLICY,
            "access_control_policy": "owner_uid_exclusive_group_no_posix_acl_v1",
            "producer_free_text_persisted": False,
            "raw_source_line_stored": False,
            "raw_chain_of_thought_stored": False,
        }
        # Cursor offsets can legitimately repeat after in-place truncation. A
        # normal append preserves that new epoch; offset-keyed append_once
        # would resurrect an old cursor and permanently repeat the reset.
        return self.store.append(_CURSOR_KIND, payload)

    def _reject(self, *, digest: str, reason: str, offset: int) -> None:
        payload = {
            "source_id": self.source_id,
            "source_path_sha256": self._source_path_digest,
            "source_record_sha256": digest,
            "reason": reason,
            "offset": offset,
            "content_policy": _CONTENT_POLICY,
            "producer_free_text_persisted": False,
            "raw_source_line_stored": False,
            "raw_chain_of_thought_stored": False,
        }
        self.store.append_once_result_guarded(
            _REJECTION_KIND,
            f"{self.source_id}:{self._source_path_digest}:{digest}:{reason}",
            payload,
            strict_existing_payload=False,
        )

    def _frames(
        self,
        *,
        offset: int,
        expected_device: int,
        expected_inode: int,
    ) -> tuple[list[_SourceFrame], int, bool]:
        frames: list[_SourceFrame] = []
        scanned_bytes = 0
        next_offset = offset
        with self.source_path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (expected_device, expected_inode):
                # The source rotated after validation but before open. Preserve
                # the old cursor and let the next tick handle the new epoch.
                return [], offset, True
            handle.seek(offset)
            while len(frames) < self.policy.max_scan_lines:
                if scanned_bytes >= self.policy.max_scan_bytes:
                    break
                before = handle.tell()
                raw = handle.readline(self.policy.max_line_bytes + 1)
                if not raw:
                    break
                complete = raw.endswith(b"\n")
                oversized = len(raw) > self.policy.max_line_bytes
                if not complete and not oversized:
                    handle.seek(before)
                    break
                after = handle.tell()
                frames.append(
                    _SourceFrame(
                        offset_before=before,
                        offset_after=after,
                        raw=raw,
                        complete=complete,
                        oversized_segment=oversized,
                    )
                )
                scanned_bytes += len(raw)
                next_offset = after
                if scanned_bytes >= self.policy.max_scan_bytes:
                    break
        return frames, next_offset, False

    def _observation(self, frame: _SourceFrame) -> tuple[Observation | None, str | None]:
        digest = sha256(frame.raw.rstrip(b"\n")).hexdigest()
        if frame.oversized_segment:
            return None, "LINE_TOO_LARGE"
        try:
            decoded = frame.raw.decode("utf-8")
            row = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None, "MALFORMED_JSON"
        if not isinstance(row, dict):
            return None, "MALFORMED_RECORD"
        try:
            timestamp = self._text(row.get("ts"), name="ts", maximum=80)
            canonical_timestamp = self._parse_time(timestamp).isoformat()
            actor = self._identifier(row.get("actor"), name="actor", maximum=80)
            project = self._identifier(
                row.get("project"), name="project", maximum=120
            )
            source_kind = self._identifier(
                row.get("kind"), name="kind", maximum=40
            ).lower()
            producer_detail = row.get("summary")
            if (
                not isinstance(producer_detail, str)
                or not producer_detail.strip()
                or len(producer_detail) > 800
            ):
                raise ValueError("summary must be a bounded non-empty string")
        except (OverflowError, TypeError, ValueError):
            return None, "MALFORMED_RECORD"
        if self.policy.projects and project not in self.policy.projects:
            return None, "PROJECT_FILTERED"
        mapped = self.KIND_POLICY.get(source_kind)
        if mapped is None:
            return None, "KIND_NOT_ALLOWED"
        cct_kind, signals = mapped
        project_ref = f"p_{sha256(project.encode('utf-8')).hexdigest()[:12]}"
        actor_ref = f"a_{sha256(actor.encode('utf-8')).hexdigest()[:12]}"
        summary = (
            f"Team-sync receipt: project_ref={project_ref}; kind={source_kind}; "
            f"actor_ref={actor_ref}; record_sha256={digest[:16]}. "
            "Producer labels and free text quarantined."
        )
        return (
            Observation(
                id=f"team_sync_{digest[:32]}",
                kind=cct_kind,
                summary=summary,
                source=f"monitor:team-sync:{project_ref}",
                confidence=1.0,
                salience=signals["salience"],
                goal_relevance=signals["goal_relevance"],
                novelty=signals["novelty"],
                urgency=signals["urgency"],
                unresolved_conflict=signals["unresolved_conflict"],
                processing_cost=0.1,
                evidence=(
                    f"team-sync:{self.source_id}:sha256:{digest}",
                    f"team-sync-actor-ref:{actor_ref}",
                    f"team-sync-project-ref:{project_ref}",
                    f"team-sync-ts:{canonical_timestamp}",
                ),
                initiative_authority="trusted_producer",
            ),
            None,
        )

    def _record_continuity(
        self,
        *,
        observed_at: datetime,
        mode: str,
        cycle_tick: int,
        observation_count: int,
    ) -> Event:
        interval = self.policy.heartbeat_interval_seconds
        bucket = int(observed_at.timestamp()) // interval
        payload = {
            "source_id": self.source_id,
            "source_path_sha256": self._source_path_digest,
            "observed_at": observed_at.astimezone(UTC).isoformat(),
            "mode": mode,
            "cycle_tick": cycle_tick,
            "observation_count": observation_count,
            "content_policy": _CONTENT_POLICY,
            "access_control_policy": "owner_uid_exclusive_group_no_posix_acl_v1",
            "producer_free_text_persisted": False,
            "llm_calls": 0,
            "external_effects": 0,
            "raw_conversation_captured": False,
            "raw_chain_of_thought_stored": False,
        }
        event, _, _ = self.store.append_once_result_guarded(
            _CONTINUITY_KIND,
            f"{self.source_id}:{self._source_path_digest}:{bucket}",
            payload,
            strict_existing_payload=False,
        )
        assert event is not None
        return event

    def _heartbeat_due(self, observed_at: datetime) -> bool:
        candidates = [value for value in (self._last_continuity_at(),) if value]
        cursor = self._cursor()
        if cursor is not None and isinstance(cursor.payload.get("observed_at"), str):
            try:
                candidates.append(self._parse_time(str(cursor.payload["observed_at"])))
            except ValueError:
                pass
        if not candidates:
            return True
        last = max(candidates)
        return (observed_at - last).total_seconds() >= self.policy.heartbeat_interval_seconds

    def run_once(self, *, observed_at: datetime | None = None) -> dict[str, Any]:
        now = observed_at or datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("observed_at must include a timezone")
        now = now.astimezone(UTC)
        source_stat = self._validate_source()
        cursor_event = self._cursor()
        if cursor_event is None:
            offset = int(source_stat.st_size) if self.policy.start_at_end else 0
            event = self._append_cursor(
                source_stat=source_stat,
                offset=offset,
                observed_at=now,
                primed=True,
                scanned_lines=0,
                accepted_events=0,
                rejected_events=0,
                cycle_tick=None,
            )
            return {
                "status": "PRIMED",
                "source_id": self.source_id,
                "offset": offset,
                "cursor_event_id": event.event_id,
                "observations": 0,
                "llm_calls": 0,
                "external_effects": 0,
            }

        cursor = cursor_event.payload
        previous_inode = int(cursor["inode"])
        previous_device = int(cursor["device"])
        previous_offset = int(cursor["offset"])
        reset_reason: str | None = None
        if (previous_device, previous_inode) != (source_stat.st_dev, source_stat.st_ino):
            reset_reason = "SOURCE_ROTATED"
        elif source_stat.st_size < previous_offset:
            reset_reason = "SOURCE_TRUNCATED"
        if reset_reason is not None:
            previous_offset = 0

        frames, next_offset, changed_during_open = self._frames(
            offset=previous_offset,
            expected_device=int(source_stat.st_dev),
            expected_inode=int(source_stat.st_ino),
        )
        if changed_during_open:
            return {
                "status": "SOURCE_CHANGED_RETRY",
                "source_id": self.source_id,
                "offset_before": previous_offset,
                "offset_after": previous_offset,
                "scanned_lines": 0,
                "observations": 0,
                "rejections": 0,
                "reset_reason": None,
                "cycle_tick": None,
                "cursor_event_id": None,
                "continuity_event_id": None,
                "llm_calls": 0,
                "external_effects": 0,
            }
        if reset_reason is not None:
            self.store.append(
                _RESET_KIND,
                {
                    "source_id": self.source_id,
                    "source_path_sha256": self._source_path_digest,
                    "reason": reset_reason,
                    "previous_device": previous_device,
                    "previous_inode": previous_inode,
                    "previous_offset": int(cursor["offset"]),
                    "new_device": int(source_stat.st_dev),
                    "new_inode": int(source_stat.st_ino),
                    "new_size": int(source_stat.st_size),
                    "raw_source_line_stored": False,
                },
            )
        observations: list[Observation] = []
        rejected = 0
        consumed_offset = previous_offset
        for frame in frames:
            observation, rejection = self._observation(frame)
            consumed_offset = frame.offset_after
            if rejection is not None:
                rejected += 1
                self._reject(
                    digest=sha256(frame.raw.rstrip(b"\n")).hexdigest(),
                    reason=rejection,
                    offset=frame.offset_before,
                )
                continue
            assert observation is not None
            observations.append(observation)
            if len(observations) >= self.policy.max_events_per_run:
                break
        if consumed_offset == previous_offset and frames:
            consumed_offset = next_offset

        cycle: dict[str, Any] | None = None
        continuity_event: Event | None = None
        if observations:
            seed_material = canonical_json(
                [observation.evidence[0] for observation in observations]
            )
            seed = int(sha256(seed_material.encode("utf-8")).hexdigest()[:16], 16)
            cycle = CognitiveCycle(AgencyKernel(self.store, self.constitution)).run(
                observations=observations,
                seed=seed,
            )
            continuity_event = self._record_continuity(
                observed_at=now,
                mode="SOURCE_EVENTS",
                cycle_tick=int(cycle["logical_tick"]),
                observation_count=len(observations),
            )
        elif not frames and self._heartbeat_due(now):
            bucket = int(now.timestamp()) // self.policy.heartbeat_interval_seconds
            cycle = CognitiveCycle(AgencyKernel(self.store, self.constitution)).run(
                observations=[],
                seed=bucket,
            )
            continuity_event = self._record_continuity(
                observed_at=now,
                mode="HOMEOSTATIC_HEARTBEAT",
                cycle_tick=int(cycle["logical_tick"]),
                observation_count=0,
            )

        cursor_result: Event | None = None
        if frames or reset_reason is not None:
            cursor_result = self._append_cursor(
                source_stat=source_stat,
                offset=consumed_offset,
                observed_at=now,
                primed=False,
                scanned_lines=len(frames),
                accepted_events=len(observations),
                rejected_events=rejected,
                cycle_tick=int(cycle["logical_tick"]) if cycle else None,
            )

        if observations:
            status = "OBSERVED"
        elif continuity_event is not None:
            status = "HEARTBEAT"
        elif frames:
            status = "ADVANCED"
        else:
            status = "IDLE"
        return {
            "status": status,
            "source_id": self.source_id,
            "offset_before": previous_offset,
            "offset_after": consumed_offset,
            "scanned_lines": len(frames),
            "observations": len(observations),
            "rejections": rejected,
            "reset_reason": reset_reason,
            "cycle_tick": int(cycle["logical_tick"]) if cycle else None,
            "cursor_event_id": cursor_result.event_id if cursor_result else None,
            "continuity_event_id": (
                continuity_event.event_id if continuity_event else None
            ),
            "llm_calls": 0,
            "external_effects": 0,
        }

    def status(self) -> dict[str, Any]:
        cursor = self._cursor()
        latest_continuity = next(
            (
                event
                for event in reversed(self.store.events(_CONTINUITY_KIND))
                if event.payload.get("source_id") == self.source_id
                and event.payload.get("source_path_sha256")
                == self._source_path_digest
            ),
            None,
        )
        return {
            "source_id": self.source_id,
            "source_path_sha256": self._source_path_digest,
            "cursor": dict(cursor.payload) if cursor else None,
            "continuity": (
                dict(latest_continuity.payload) if latest_continuity else None
            ),
            "policy": {
                "max_events_per_run": self.policy.max_events_per_run,
                "max_scan_lines": self.policy.max_scan_lines,
                "max_scan_bytes": self.policy.max_scan_bytes,
                "max_line_bytes": self.policy.max_line_bytes,
                "heartbeat_interval_seconds": self.policy.heartbeat_interval_seconds,
                "start_at_end": self.policy.start_at_end,
                "projects": list(self.policy.projects),
            },
            "initiative_authority": "trusted_producer",
            "same_uid_host_boundary": True,
            "llm_calls": 0,
            "external_effects": 0,
            "raw_conversation_captured": False,
            "raw_chain_of_thought_stored": False,
        }
