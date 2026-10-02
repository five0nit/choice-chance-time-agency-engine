"""Host-owned research catalog and ticketed, public-only GET execution.

The producer chooses catalog IDs, never URLs, paths, credentials or capabilities.
Reuse CCT's DNS-pinned transport, leases, ticket mediation and hash receipts.
"""
from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
from html.parser import HTMLParser
import json
from types import MappingProxyType
from typing import Literal, Mapping
from urllib.parse import urlencode, urlsplit

from .capabilities import CapabilityLease, CapabilityRegistry, OperatorCapabilityCatalog
from .execution_tickets import ExecutionTicket, ExecutionTicketAuthority
from .mediation import ToolExecutionMediator
from .owner_discovery import now, stamp
from .principal import PrincipalDirective, PrincipalModel, PrincipalProfile
from .research import OperatorWebAdapter, OperatorWebSource, MAX_OPERATOR_WEB_BYTES
from .store import canonical_json

MAX_BYTES = MAX_OPERATOR_WEB_BYTES
MAX_SOURCES = 6
CATALOG = (
    {"id": "dexscreener-docs", "title": "DEX Screener API fields and limits",
     "url": "https://docs.dexscreener.com/api/reference.md"},
    {"id": "solana-fees", "title": "Solana transaction fee mechanics",
     "url": "https://solana.com/docs/core/fees.md"},
    {"id": "coingecko-limits", "title": "CoinGecko API access and rate limits",
     "url": "https://docs.coingecko.com/docs/errors-and-rate-limits.md"},
    {"id": "kraken-pair", "title": "Kraken public BTC/USD minimums and fee tiers (not account eligibility)",
     "url": "https://api.kraken.com/0/public/AssetPairs?pair=XBTUSD"},
    {"id": "kraken-price", "title": "Kraken BTC/USD public ticker snapshot (not an executable quote)",
     "url": "https://api.kraken.com/0/public/Ticker?pair=XBTUSD"},
    {"id": "kraken-spread", "title": "Kraken BTC/USD public order book snapshot (not guaranteed fills)",
     "url": "https://api.kraken.com/0/public/Depth?pair=XBTUSD"},
)


# Opt-in host constants only. Never merge these into the legacy default CATALOG.
DOCUMENTATION_CATALOG = (
    {"id": "python-tomllib", "title": "Python TOML parsing and error handling",
     "url": "https://docs.python.org/3/library/tomllib.html"},
    {"id": "python-venv", "title": "Python virtual environments",
     "url": "https://docs.python.org/3/library/venv.html"},
    {"id": "packaging-pyproject", "title": "Python pyproject.toml packaging guide",
     "url": "https://packaging.python.org/en/latest/guides/writing-pyproject-toml/"},
    {"id": "pytest-exit-codes", "title": "pytest documented exit codes",
     "url": "https://docs.pytest.org/en/stable/reference/exit-codes.html"},
)
WorkSourceId = Literal["dexscreener-docs", "solana-fees", "coingecko-limits",
    "kraken-pair", "kraken-price", "kraken-spread", "python-tomllib", "python-venv",
    "packaging-pyproject", "pytest-exit-codes"]
_INSTALLED_CATALOG_JSON = canonical_json(CATALOG + DOCUMENTATION_CATALOG)
_INSTALLED = MappingProxyType({entry["id"]: MappingProxyType(dict(entry))
                               for entry in CATALOG + DOCUMENTATION_CATALOG})


def select_catalog(source_ids: list[str] | tuple[str, ...] | None = None) -> tuple[Mapping[str, str], ...]:
    """Host selects exact installed IDs, not URLs, aliases or path prefixes."""
    if canonical_json(CATALOG + DOCUMENTATION_CATALOG) != _INSTALLED_CATALOG_JSON:
        raise ValueError("WORK_CATALOG_CHANGED")
    if source_ids is None:
        source_ids = tuple(entry["id"] for entry in CATALOG)
    if (type(source_ids) not in (list, tuple) or not 1 <= len(source_ids) <= len(_INSTALLED)
            or any(type(sid) is not str or sid not in _INSTALLED for sid in source_ids)
            or len(set(source_ids)) != len(source_ids)):
        raise ValueError("WORK_CATALOG_INVALID")
    entries = tuple(_INSTALLED[sid] for sid in source_ids)
    if len({entry["url"] for entry in entries}) != len(entries):
        raise ValueError("WORK_CATALOG_INVALID")
    return entries


class PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.hidden = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


def page_text(content, content_type):
    if content_type != "text/html":
        return content
    parser = PageText()
    parser.feed(content)
    return "\n".join(parser.parts)


class WorkWeb:
    def __init__(self, store, owner_uid, authorization, *, source_ids=None):
        self.catalog = select_catalog(source_ids)
        self.store, self.owner_uid, self.authorization = store, owner_uid, authorization
        self.profile = PrincipalModel(store).install(PrincipalProfile(
            principal_id=owner_uid, display_name="CCT owner",
            values={"truth": 1.0, "competence": 1.0},
            directives=(PrincipalDirective(id="owner-work-research", kind="preference",
                statement="Research saved discovery ideas using bounded public GET and private reports only.",
                tags=("domain:operator", "action:web"), priority=80),)),
            authority="operator", evidence=(authorization,))["profile_digest"]
        self.spec = OperatorCapabilityCatalog(store).install()["web"]["spec_digest"]
        sources = []
        for entry in self.catalog:
            url = urlsplit(entry["url"])
            sources.append(OperatorWebSource(
                id=entry["id"], base_url=f"https://{url.hostname}",
                allowed_content_types=("application/json", "text/plain", "text/markdown", "text/html"),
                max_bytes=MAX_BYTES, timeout_ms=10_000,
                fetch_path_prefixes=(url.path,), search_path=url.path if url.query else None,
                search_parameter="pair" if url.query else None))
        self.adapter = OperatorWebAdapter(store, sources=sources)
        self.mediator = ToolExecutionMediator(store, frozenset({"operator_web"}),
                                              outcome_verifiers=self.adapter.outcome_verifiers())

    def fetch(self, job_id, plan, source_id: WorkSourceId):
        if type(source_id) is not str or source_id not in {item["id"] for item in self.catalog}:
            raise ValueError("WORK_SOURCE_NOT_ALLOWED")
        entry = next(item for item in self.catalog if item["id"] == source_id)
        url = urlsplit(entry["url"])
        ticket_id = f"{job_id}-{source_id}"
        scope, expiry = f"operator/web/{source_id}", stamp(now() + timedelta(minutes=3))
        args = {"execution_ticket_id": ticket_id, "source_id": source_id,
                "max_bytes": MAX_BYTES, "timeout_ms": 10_000}
        if url.query:
            # Exact host catalog constant, never owner/model text in external queries.
            if url.query != urlencode({"pair": "XBTUSD"}):
                raise ValueError("WORK_CATALOG_QUERY_INVALID")
            args.update(operation="search", query="XBTUSD")
        else:
            args.update(operation="fetch", path=url.path)
        lease_id = "lease-" + ticket_id
        CapabilityRegistry(self.store).grant(CapabilityLease(
            id=lease_id, capability="operator.web", principal_id=self.owner_uid,
            scopes=(scope,), expires_at=expiry, max_actions=1, max_bytes=MAX_BYTES,
            max_value_microunits=0, issued_by="operator", evidence=(self.authorization,)))
        ExecutionTicketAuthority(self.store).issue(ExecutionTicket(
            id=ticket_id, tool_name="operator_web",
            arguments_sha256=sha256(canonical_json(args).encode()).hexdigest(),
            goal_id=job_id, plan_id=job_id, plan_hash=sha256(canonical_json(plan).encode()).hexdigest(),
            stage="public-research", attempt=1, principal_id=self.owner_uid,
            principal_profile_digest=self.profile, capability="operator.web",
            capability_spec_digest=self.spec, lease_id=lease_id, scope=scope,
            expires_at=expiry, action_budget=1, byte_budget=MAX_BYTES, value_budget_microunits=0),
            authority="operator", evidence=(self.authorization,))
        raw = self.mediator(tool_name="operator_web", args=args, original_args=args,
                            next_call=lambda: self.adapter.execute(args))
        result = json.loads(raw) if isinstance(raw, str) else raw
        if result.get("success") is not True or not result.get("web", {}).get("content"):
            raise RuntimeError("WORK_WEB_NO_USABLE_RECEIPT")
        web = result["web"]
        content = web["content"]
        text = page_text(content, web["content_type"])
        return {**entry, "ok": True, "fetchedAt": stamp(), "ticketId": ticket_id,
                "sha256": sha256(content.encode()).hexdigest(),
                "text": text[:18_000], "textTruncated": len(text) > 18_000,
                "contentType": web["content_type"], "receipt": result}
