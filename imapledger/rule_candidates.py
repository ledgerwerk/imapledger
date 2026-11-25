from __future__ import annotations

from dataclasses import dataclass

from .message import MailMessage
from .rules import RuleError, RuleMatch, describe_match


@dataclass(frozen=True, slots=True)
class RuleCandidate:
    id: str
    match: RuleMatch
    description: str
    auto_safe: bool
    specificity: int


def build_rule_candidates(message: MailMessage) -> tuple[RuleCandidate, ...]:
    candidates: list[RuleCandidate] = []
    seen: set[tuple[tuple[str, str], ...]] = set()

    def add(candidate_id: str, match: RuleMatch, *, auto_safe: bool, specificity: int) -> None:
        identity = tuple(match.as_dict().items())
        if identity in seen:
            return
        seen.add(identity)
        candidates.append(
            RuleCandidate(
                id=candidate_id,
                match=match,
                description=describe_match(match),
                auto_safe=auto_safe,
                specificity=specificity,
            )
        )

    sender_match = _candidate_match(from_address=message.from_address)
    if sender_match is not None:
        add("from_address_exact", sender_match, auto_safe=True, specificity=100)
        if message.auto_submitted.strip():
            add(
                "from_address_and_auto_submitted",
                RuleMatch(from_address=message.from_address, auto_submitted=message.auto_submitted),
                auto_safe=True,
                specificity=110,
            )
        subject_prefix = _conservative_subject_prefix(message.subject)
        if subject_prefix:
            add(
                "from_address_and_subject_prefix",
                RuleMatch(from_address=message.from_address, subject_prefix=subject_prefix),
                auto_safe=True,
                specificity=110,
            )
        sender_domain = _address_domain(message.from_address)
        if sender_domain:
            add("from_domain_exact", RuleMatch(from_domain=sender_domain), auto_safe=False, specificity=20)

    if message.list_id.strip():
        add("list_id_exact", RuleMatch(list_id=message.list_id), auto_safe=True, specificity=100)
    if message.return_path.strip():
        return_match = _candidate_match(return_path=message.return_path)
        if return_match is not None:
            add("return_path_address_exact", return_match, auto_safe=True, specificity=100)
            return_domain = _address_domain(message.return_path)
            if return_domain:
                add(
                    "return_path_domain_exact",
                    RuleMatch(return_path_domain=return_domain),
                    auto_safe=False,
                    specificity=20,
                )

    if message.subject.strip():
        add("subject_exact", RuleMatch(subject=message.subject), auto_safe=False, specificity=10)
        subject_prefix = _conservative_subject_prefix(message.subject)
        if subject_prefix:
            add("subject_prefix", RuleMatch(subject_prefix=subject_prefix), auto_safe=False, specificity=5)
    return tuple(candidates)


def _candidate_match(**values: str) -> RuleMatch | None:
    try:
        return RuleMatch(**values)
    except RuleError:
        return None


def _address_domain(address: str) -> str | None:
    if address.count("@") != 1:
        return None
    return address.rsplit("@", 1)[1].strip().rstrip(".").casefold() or None


def _conservative_subject_prefix(subject: str) -> str:
    prefix = subject[:64]
    if len(subject) > 64 and " " in prefix:
        prefix = prefix.rsplit(" ", 1)[0]
    return prefix.rstrip()
