"""Host-bound conversion of one exact private gateway reply into CCT metadata.

The Hermes ``pre_gateway_dispatch`` hook runs before normal gateway authorization.
This adapter therefore repeats the gateway's own authorization check, requires the
same private Telegram recipient binding used by the verified outbound proposal,
and accepts only a closed metadata grammar. Raw user text and platform identifiers
never enter the CCT ledger.
"""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import re
import stat

from .clarification_dialogue import (
    ClarificationAnswer,
    ClarificationConfirmation,
    ClarificationDenied,
    ClarificationDialogue,
    QuestionAnswer,
)
from .principal import PrincipalModel
from .pursuit_dialogue import PursuitDialogue, PursuitDialogueDenied, PursuitReply
from .store import Event, EventStore, canonical_json


_PREFIX = "CCT REPLY "
_COMMAND = re.compile(
    r"^CCT REPLY "
    r"(?P<proposal>[A-Za-z0-9][A-Za-z0-9._:-]{0,159}) "
    r"r(?P<revision>[1-9][0-9]{0,9}) "
    r"portfolio=(?P<portfolio>[0-9a-f]{64}) "
    r"(?P<decision>ACTIVATE|REDIRECT|REJECT|CLOSE) "
    r"(?P<selected>[A-Za-z0-9][A-Za-z0-9._:-]{0,159})$"
)
_CONFIRM_PREFIX = "CCT CONFIRM "
_CONFIRM_COMMAND = re.compile(
    r"^CCT CONFIRM "
    r"(?P<request>[A-Za-z0-9][A-Za-z0-9._:-]{0,159}) "
    r"r(?P<revision>[1-9][0-9]{0,9}) "
    r"request=(?P<request_sha>[0-9a-f]{64}) "
    r"answer=(?P<answer_sha>[0-9a-f]{64})$"
)
_CLARIFICATION_BINDING = re.compile(
    r"Binding: (?P<request>[A-Za-z0-9][A-Za-z0-9._:-]{0,159}) "
    r"r(?P<revision>[1-9][0-9]{0,9}) "
    r"request=(?P<request_sha>[0-9a-f]{64})"
)
_SECRET_FILENAME = "pursuit-reply-auth.key"
_MAX_COMMAND_CHARS = 512
_MAX_SECRET_BYTES = 256


class GatewayPursuitReplyDenied(RuntimeError):
    """Fail-closed gateway reply conversion with one bounded reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _digest(value: object) -> str:
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _skip(reason: str) -> dict[str, str]:
    return {"action": "skip", "reason": reason}


def _platform_name(value: object) -> str:
    return str(getattr(value, "value", value) or "").strip().lower()


class GatewayPursuitReplyAdapter:
    """Apply one exact operator reply at the non-model-callable gateway edge."""

    def __init__(self, store: EventStore, *, secret_path: Path | None = None) -> None:
        if not isinstance(store, EventStore):
            raise TypeError("store must be an EventStore")
        self.store = store
        expected = store.path.parent / _SECRET_FILENAME
        configured = Path(secret_path) if secret_path is not None else expected
        if configured.absolute() != expected.absolute():
            raise ValueError("reply secret must use the profile-local registered path")
        self.secret_path = configured.absolute()

    @staticmethod
    def _is_natural_clarification_candidate(event: object) -> bool:
        text = getattr(event, "text", None)
        reply_to_text = getattr(event, "reply_to_text", None)
        return (
            isinstance(text, str)
            and bool(text.strip())
            and not text.startswith((_PREFIX, _CONFIRM_PREFIX))
            and isinstance(reply_to_text, str)
            and reply_to_text.startswith("CCT clarification:")
            and getattr(event, "reply_to_is_own_message", None) is True
        )

    @staticmethod
    def is_candidate(event: object) -> bool:
        text = getattr(event, "text", None)
        return (
            isinstance(text, str)
            and (text.startswith(_PREFIX) or text.startswith(_CONFIRM_PREFIX))
        ) or GatewayPursuitReplyAdapter._is_natural_clarification_candidate(event)

    def _secret(self) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = -1
        try:
            fd = os.open(self.secret_path, flags | getattr(os, "O_NONBLOCK", 0))
            metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
                or not 32 <= metadata.st_size <= _MAX_SECRET_BYTES
            ):
                raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_SECRET_INVALID")
            secret = os.read(fd, _MAX_SECRET_BYTES + 1)
            if not 32 <= len(secret) <= _MAX_SECRET_BYTES:
                raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_SECRET_INVALID")
            return secret
        except GatewayPursuitReplyDenied:
            raise
        except OSError as error:
            raise GatewayPursuitReplyDenied(
                "CCT_PURSUIT_REPLY_SECRET_INVALID"
            ) from error
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _authorized_source(event: object, gateway: object) -> tuple[object, str, str]:
        source = getattr(event, "source", None)
        if source is None:
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_SOURCE_INVALID")
        authorizer = getattr(gateway, "_is_user_authorized", None)
        try:
            authorized = callable(authorizer) and authorizer(source) is True
        except Exception as error:
            raise GatewayPursuitReplyDenied(
                "CCT_PURSUIT_REPLY_UNAUTHORIZED"
            ) from error
        if not authorized:
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_UNAUTHORIZED")
        if _platform_name(getattr(source, "platform", None)) != "telegram":
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_TELEGRAM_REQUIRED")
        if getattr(source, "chat_type", None) != "dm":
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_PRIVATE_DM_REQUIRED")
        if getattr(source, "profile", None) not in {None, "generalist2"}:
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_PROFILE_MISMATCH")
        chat_id = getattr(source, "chat_id", None)
        user_id = getattr(source, "user_id", None)
        if (
            not isinstance(chat_id, str)
            or not chat_id
            or len(chat_id) > 160
            or not isinstance(user_id, str)
            or not user_id
            or len(user_id) > 160
        ):
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_SOURCE_INVALID")
        event_user_id = getattr(event, "user_id", None)
        if event_user_id is not None and str(event_user_id) != user_id:
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_SOURCE_INVALID")
        if getattr(event, "media_urls", None):
            raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_TEXT_ONLY")
        return source, chat_id, user_id

    @staticmethod
    def _latest_proposal(events: list[Event], proposal_id: str) -> Event | None:
        proposals = [
            row
            for row in events
            if row.kind == "pursuit.dialogue.proposed"
            and row.payload.get("proposal_id") == proposal_id
        ]
        return (
            max(proposals, key=lambda row: int(row.payload.get("revision", 0)))
            if proposals
            else None
        )

    @staticmethod
    def _delivery_binding(events: list[Event], proposal: Event) -> str | None:
        rows = [
            row
            for row in events
            if row.kind == "canary.telegram.delivery.completed"
            and row.payload.get("proposal_event_id") == proposal.event_id
            and row.payload.get("proposal_id") == proposal.payload.get("proposal_id")
            and row.payload.get("proposal_revision") == proposal.payload.get("revision")
            and row.payload.get("portfolio_sha256")
            == proposal.payload.get("portfolio_sha256")
            and row.payload.get("principal_id") == "mike"
            and row.payload.get("profile_name") == "generalist2"
            and row.payload.get("service_name")
            == "hermes-gateway-generalist2.service"
            and row.payload.get("platform") == "telegram"
            and row.payload.get("chat_type") == "private"
            and row.payload.get("delivery_readback_verified") is True
            and row.payload.get("status") == "delivered"
            and row.payload.get("external_effect_count") == 1
        ]
        bindings = {
            str(row.payload.get("recipient_binding_sha256"))
            for row in rows
            if re.fullmatch(
                r"[0-9a-f]{64}", str(row.payload.get("recipient_binding_sha256", ""))
            )
        }
        return next(iter(bindings)) if len(bindings) == 1 else None

    @staticmethod
    def _latest_clarification(events: list[Event], request_id: str) -> Event | None:
        rows = [
            row
            for row in events
            if row.kind == "clarification.requested"
            and row.payload.get("request_id") == request_id
        ]
        return (
            max(rows, key=lambda row: int(row.payload.get("revision", 0)))
            if rows
            else None
        )

    @staticmethod
    def _clarification_reply_binding(
        events: list[Event], request: Event, reply_to_text: str
    ) -> bool:
        binding = _CLARIFICATION_BINDING.search(reply_to_text)
        if (
            binding is None
            or binding["request"] != request.payload.get("request_id")
            or int(binding["revision"]) != request.payload.get("revision")
            or binding["request_sha"] != request.payload.get("request_sha256")
        ):
            return False
        packet_id = "packet_clarification_" + _digest(
            {"request_event_id": request.event_id}
        )[:20]
        return any(
            event.kind == "proactive.message.emitted"
            and event.payload.get("packet_id") == packet_id
            and event.payload.get("message") == reply_to_text
            for event in events
        )

    @staticmethod
    def _option_value(text: str, options: list[object]) -> str | None:
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", text.strip()).strip("_").upper()
        matches = [str(option) for option in options if str(option).upper() == normalized]
        return matches[0] if len(matches) == 1 else None

    @classmethod
    def _natural_answers(cls, request: Event, text: str) -> tuple[QuestionAnswer, ...] | None:
        questions = list(request.payload.get("questions", []))
        if not questions or any(row.get("answer_type") != "OPTION" for row in questions):
            return None
        if len(questions) == 1:
            value = cls._option_value(text, list(questions[0].get("options", [])))
            return (
                QuestionAnswer(str(questions[0]["id"]), "OPTION", value),
            ) if value is not None else None
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) != len(questions):
            return None
        raw: dict[str, str] = {}
        for line in lines:
            if ":" not in line:
                return None
            key, value = line.split(":", 1)
            normalized_key = re.sub(r"[^A-Za-z0-9]+", "-", key.strip()).strip("-").casefold()
            if normalized_key in raw:
                return None
            raw[normalized_key] = value.strip()
        answers = []
        for question in questions:
            key = str(question["id"]).casefold()
            value = cls._option_value(raw.get(key, ""), list(question.get("options", [])))
            if value is None:
                return None
            answers.append(QuestionAnswer(str(question["id"]), "OPTION", value))
        return tuple(answers)

    def _handle_natural_clarification(
        self, *, event: object, gateway: object
    ) -> dict[str, str] | None:
        text = getattr(event, "text", None)
        reply_to_text = getattr(event, "reply_to_text", None)
        reply_to_message_id = getattr(event, "reply_to_message_id", None)
        if (
            not isinstance(text, str)
            or not text.strip()
            or len(text) > 1200
            or not isinstance(reply_to_text, str)
            or len(reply_to_text) > 1800
            or not isinstance(reply_to_message_id, str)
            or not reply_to_message_id
            or len(reply_to_message_id) > 160
            or getattr(event, "reply_to_is_own_message", None) is not True
        ):
            return None
        binding = _CLARIFICATION_BINDING.search(reply_to_text)
        if binding is None:
            return None
        try:
            _source, chat_id, user_id = self._authorized_source(event, gateway)
            if self.store.verify_chain().get("valid") is not True:
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_NATURAL_LEDGER_INVALID"
                )
            events = self.store.events()
            request = self._latest_clarification(events, binding["request"])
            if (
                request is None
                or request.payload.get("revision") != int(binding["revision"])
                or request.payload.get("request_sha256") != binding["request_sha"]
                or not self._clarification_reply_binding(events, request, reply_to_text)
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_NATURAL_REQUEST_MISMATCH"
                )
            answers = self._natural_answers(request, text)
            if answers is None:
                return None
            message_id = getattr(event, "message_id", None)
            if not isinstance(message_id, str) or not message_id or len(message_id) > 160:
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_NATURAL_MESSAGE_ID_REQUIRED"
                )
            profile = PrincipalModel(self.store).status()
            principal = profile.get("profile")
            if (
                not isinstance(principal, dict)
                or principal.get("principal_id") != "mike"
                or profile.get("profile_digest")
                != request.payload.get("principal_profile_digest")
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_NATURAL_PRINCIPAL_MISMATCH"
                )
            message_id_sha256 = sha256(message_id.encode("utf-8")).hexdigest()
            recipient_binding = _digest(
                {
                    "profile_name": "generalist2",
                    "platform": "telegram",
                    "chat_type": "private",
                    "principal_id": "mike",
                    "chat_id": chat_id,
                    "user_id": user_id,
                }
            )
            answer_id = "gateway-answer-" + _digest(
                {
                    "request_event_id": request.event_id,
                    "message_id_sha256": message_id_sha256,
                    "reply_to_message_id_sha256": sha256(
                        reply_to_message_id.encode("utf-8")
                    ).hexdigest(),
                    "recipient_binding_sha256": recipient_binding,
                }
            )[:32]
            ClarificationDialogue(self.store).record_understanding(
                ClarificationAnswer(
                    id=answer_id,
                    request_id=str(request.payload["request_id"]),
                    request_revision=int(request.payload["revision"]),
                    request_sha256=str(request.payload["request_sha256"]),
                    principal_id="mike",
                    principal_profile_digest=str(profile["profile_digest"]),
                    answers=answers,
                    evidence=(f"telegram:{message_id_sha256}",),
                    source_authority="host_adapter",
                )
            )
        except GatewayPursuitReplyDenied as error:
            return _skip(error.reason_code)
        except ClarificationDenied as error:
            return _skip(f"CCT_CLARIFICATION_NATURAL_{error.reason_code}")
        except (TypeError, ValueError):
            return None
        # Keep the authenticated natural reply in the ordinary Hermes turn so the
        # model can respond conversationally. The pre-LLM context now carries the
        # independently persisted allowlisted option value.
        return None

    def _handle_clarification_confirmation(
        self,
        *,
        event: object,
        gateway: object,
        text: str,
    ) -> dict[str, str]:
        match = _CONFIRM_COMMAND.fullmatch(text)
        if match is None:
            return _skip("CCT_CLARIFICATION_CONFIRMATION_MALFORMED")
        try:
            _source, chat_id, user_id = self._authorized_source(event, gateway)
            if self.store.verify_chain().get("valid") is not True:
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_LEDGER_INVALID"
                )
            events = self.store.events()
            request = self._latest_clarification(events, match["request"])
            revision = int(match["revision"])
            if (
                request is None
                or request.payload.get("revision") != revision
                or request.payload.get("request_sha256") != match["request_sha"]
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_REQUEST_MISMATCH"
                )
            answers = [
                row
                for row in events
                if row.kind == "clarification.answer.understood"
                and row.payload.get("request_event_id") == request.event_id
                and row.payload.get("answer_sha256") == match["answer_sha"]
            ]
            if len(answers) != 1:
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_ANSWER_MISMATCH"
                )
            answer = answers[0]
            reply_to_text = getattr(event, "reply_to_text", None)
            reply_to_message_id = getattr(event, "reply_to_message_id", None)
            if (
                not isinstance(reply_to_text, str)
                or len(reply_to_text) > 1800
                or not isinstance(reply_to_message_id, str)
                or not reply_to_message_id
                or len(reply_to_message_id) > 160
                or getattr(event, "reply_to_is_own_message", None) is not True
                or not self._clarification_reply_binding(events, request, reply_to_text)
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_RECIPIENT_MISMATCH"
                )
            inbound_binding = _digest(
                {
                    "profile_name": "generalist2",
                    "platform": "telegram",
                    "chat_type": "private",
                    "principal_id": "mike",
                    "chat_id": chat_id,
                    "user_id": user_id,
                }
            )
            message_id = getattr(event, "message_id", None)
            if not isinstance(message_id, str) or not message_id or len(message_id) > 160:
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_MESSAGE_ID_REQUIRED"
                )
            profile = PrincipalModel(self.store).status()
            principal = profile.get("profile")
            if (
                not isinstance(principal, dict)
                or principal.get("principal_id") != "mike"
                or profile.get("profile_digest")
                != request.payload.get("principal_profile_digest")
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_CLARIFICATION_CONFIRMATION_PRINCIPAL_MISMATCH"
                )
            message_id_sha256 = sha256(message_id.encode("utf-8")).hexdigest()
            confirmation_id = "gateway-confirmation-" + _digest(
                {
                    "platform": "telegram",
                    "message_id_sha256": message_id_sha256,
                    "recipient_binding_sha256": inbound_binding,
                    "request_event_id": request.event_id,
                    "answer_event_id": answer.event_id,
                }
            )[:32]
            secret = self._secret()
            confirmation = ClarificationConfirmation.sign(
                confirmation_id=confirmation_id,
                request_id=str(request.payload["request_id"]),
                request_revision=revision,
                request_sha256=str(request.payload["request_sha256"]),
                answer_event_id=answer.event_id,
                answer_sha256=str(answer.payload["answer_sha256"]),
                principal_id="mike",
                principal_profile_digest=str(profile["profile_digest"]),
                evidence=(f"telegram:{message_id_sha256}",),
                source_authority="operator",
                secret=secret,
            )
            result = ClarificationDialogue(self.store).confirm(
                confirmation, secret=secret
            )
        except GatewayPursuitReplyDenied as error:
            return _skip(error.reason_code)
        except ClarificationDenied as error:
            return _skip(f"CCT_CLARIFICATION_CONFIRMATION_{error.reason_code}")
        except (TypeError, ValueError):
            return _skip("CCT_CLARIFICATION_CONFIRMATION_MALFORMED")
        return _skip(
            "CCT_CLARIFICATION_CONFIRMATION_APPLIED"
            if result.get("confirmed") is True
            else "CCT_CLARIFICATION_CONFIRMATION_DUPLICATE"
        )

    def handle(self, *, event: object, gateway: object) -> dict[str, str] | None:
        """Consume exact CCT replies; return ``None`` for unrelated user text."""

        if not self.is_candidate(event):
            return None
        if self._is_natural_clarification_candidate(event):
            return self._handle_natural_clarification(event=event, gateway=gateway)
        text = getattr(event, "text", "")
        if not isinstance(text, str) or len(text) > _MAX_COMMAND_CHARS:
            return _skip(
                "CCT_CLARIFICATION_CONFIRMATION_MALFORMED"
                if isinstance(text, str) and text.startswith(_CONFIRM_PREFIX)
                else "CCT_PURSUIT_REPLY_MALFORMED"
            )
        if text.startswith(_CONFIRM_PREFIX):
            return self._handle_clarification_confirmation(
                event=event,
                gateway=gateway,
                text=text,
            )
        match = _COMMAND.fullmatch(text)
        if match is None:
            return _skip("CCT_PURSUIT_REPLY_MALFORMED")
        try:
            _source, chat_id, user_id = self._authorized_source(event, gateway)
            if self.store.verify_chain().get("valid") is not True:
                raise GatewayPursuitReplyDenied("CCT_PURSUIT_REPLY_LEDGER_INVALID")
            events = self.store.events()
            proposal = self._latest_proposal(events, match["proposal"])
            revision = int(match["revision"])
            if (
                proposal is None
                or proposal.payload.get("revision") != revision
                or proposal.payload.get("portfolio_sha256") != match["portfolio"]
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_PURSUIT_REPLY_PROPOSAL_MISMATCH"
                )
            binding = self._delivery_binding(events, proposal)
            inbound_binding = _digest(
                {
                    "profile_name": "generalist2",
                    "platform": "telegram",
                    "chat_type": "private",
                    "principal_id": "mike",
                    "chat_id": chat_id,
                    "user_id": user_id,
                }
            )
            if binding is None or binding != inbound_binding:
                raise GatewayPursuitReplyDenied(
                    "CCT_PURSUIT_REPLY_RECIPIENT_MISMATCH"
                )
            message_id = getattr(event, "message_id", None)
            if not isinstance(message_id, str) or not message_id or len(message_id) > 160:
                raise GatewayPursuitReplyDenied(
                    "CCT_PURSUIT_REPLY_MESSAGE_ID_REQUIRED"
                )
            profile = PrincipalModel(self.store).status()
            principal = profile.get("profile")
            if (
                not isinstance(principal, dict)
                or principal.get("principal_id") != "mike"
                or profile.get("profile_digest")
                != proposal.payload.get("principal_profile_digest")
            ):
                raise GatewayPursuitReplyDenied(
                    "CCT_PURSUIT_REPLY_PRINCIPAL_MISMATCH"
                )
            message_id_sha256 = sha256(message_id.encode("utf-8")).hexdigest()
            reply_id = "gateway-reply-" + _digest(
                {
                    "platform": "telegram",
                    "message_id_sha256": message_id_sha256,
                    "recipient_binding_sha256": inbound_binding,
                    "proposal_event_id": proposal.event_id,
                }
            )[:32]
            secret = self._secret()
            reply = PursuitReply.sign(
                reply_id=reply_id,
                proposal_id=match["proposal"],
                proposal_revision=revision,
                portfolio_sha256=match["portfolio"],
                principal_id="mike",
                principal_profile_digest=str(profile["profile_digest"]),
                decision=match["decision"],
                selected_pursuit_id=match["selected"],
                evidence=(f"telegram:{message_id_sha256}",),
                source_authority="operator",
                semantic_taint=False,
                secret=secret,
            )
            result = PursuitDialogue(self.store).record_reply(
                reply, secret=secret
            )
        except GatewayPursuitReplyDenied as error:
            return _skip(error.reason_code)
        except PursuitDialogueDenied as error:
            return _skip(f"CCT_PURSUIT_REPLY_{error.reason_code}")
        except (TypeError, ValueError):
            return _skip("CCT_PURSUIT_REPLY_MALFORMED")
        return _skip(
            "CCT_PURSUIT_REPLY_APPLIED"
            if result.get("applied") is True
            else "CCT_PURSUIT_REPLY_DUPLICATE"
        )
