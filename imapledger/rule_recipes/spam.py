from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path

from pyjev.decisions import BundleDecision, NoulDecision, load_decision

from ..evidence import MessageEvidence
from ..routing_actions import RuleAction
from ..routing_models import EvaluationState, RoutingRule, RuleType
from .models import RecipeEvaluation, RecipeOptionSpec, RuleRecipeSpec

SIGNAL_NAMES = (
    "unsolicited_bulk",
    "phishing_or_scam",
    "identity_deception",
    "legitimate_expected",
    "action_safe",
)

_OPTION_SPECS = (
    RecipeOptionSpec(
        "legitimate_veto_at",
        "Legitimate-message veto",
        "Confidence that expected mail must override a Spam match.",
        0.80,
    ),
    RecipeOptionSpec(
        "phishing_match_at",
        "Phishing match threshold",
        "Confidence required for an immediate scam or phishing match.",
        0.90,
    ),
    RecipeOptionSpec(
        "identity_deception_at",
        "Identity-deception threshold",
        "Confidence required before identity deception can contribute to a match.",
        0.90,
    ),
    RecipeOptionSpec(
        "unsolicited_bulk_at",
        "Unsolicited-bulk threshold",
        "Confidence required before unsolicited bulk can contribute to a match.",
        0.92,
    ),
    RecipeOptionSpec(
        "action_safe_at",
        "Safe-automation threshold",
        "Corroboration required for an automatic Spam match.",
        0.88,
    ),
    RecipeOptionSpec(
        "provider_junk_support_at",
        "Provider-evidence threshold",
        "Corroboration required when trusted provider Spam evidence is present.",
        0.80,
    ),
)

SPAM_RECIPE_SPEC = RuleRecipeSpec(
    id="spam",
    title="Spam / scam",
    category="Safety",
    summary="Conservative multi-signal detection for scams, phishing, impersonation, and unwanted bulk mail.",
    description=(
        "Combines five model signals with trusted authentication and provider evidence. "
        "Strong legitimate-message evidence vetoes a match; uncertain evidence is a non-match. "
        "The rule's configured action is applied only when this detector matches."
    ),
    default_rule_id="spam",
    produces_type=RuleType.RECIPE,
    default_action=RuleAction.MOVE,
    runtime_recipe="spam",
    options_schema=_OPTION_SPECS,
    uses_model=True,
    destructive=False,
    revision="spam-v2",
)


class SpamRecipe:
    spec = SPAM_RECIPE_SPEC

    def __init__(self, *, decision_path: Path | None = None) -> None:
        self._decision_path = decision_path or Path(__file__).parents[1] / "decisions.toml"

    def validate_options(self, options: Mapping[str, object]) -> Mapping[str, object]:
        if not isinstance(options, Mapping):
            raise ValueError("Spam recipe options must be a table")
        defaults = {option.key: option.default for option in _OPTION_SPECS}
        unknown = set(options) - set(defaults)
        if unknown:
            raise ValueError(f"unknown Spam recipe option: {sorted(unknown)[0]}")
        validated = defaults.copy()
        for key, value in options.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Spam recipe option {key} must be a probability")
            probability = float(value)
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise ValueError(f"Spam recipe option {key} must be between 0 and 1")
            validated[key] = probability
        return validated

    def questions(self, *, rule: RoutingRule) -> Mapping[str, NoulDecision]:
        self.validate_options(rule.options)
        decision = load_decision("spam-evidence", config=self._decision_path)
        if not isinstance(decision, BundleDecision):
            raise TypeError("spam-evidence decision must be a BundleDecision")
        if not set(SIGNAL_NAMES).issubset(decision.questions):
            raise ValueError("spam-evidence bundle is missing a required question")
        questions = {name: decision.questions[name] for name in SIGNAL_NAMES}
        if any(not isinstance(question, NoulDecision) for question in questions.values()):
            raise TypeError("all Spam recipe questions must be Noul decisions")
        return questions

    def interpret(
        self,
        *,
        rule: RoutingRule,
        results: Mapping[str, float],
        evidence: MessageEvidence,
    ) -> RecipeEvaluation:
        options = self.validate_options(rule.options)
        if set(results) != set(SIGNAL_NAMES):
            raise ValueError("Spam recipe results are missing required signals")
        for name, value in results.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Spam signal {name} must be a finite probability in [0, 1]")
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"Spam signal {name} must be a finite probability in [0, 1]")

        legitimate = float(results["legitimate_expected"])
        action_safe = float(results["action_safe"])
        if legitimate >= options["legitimate_veto_at"]:
            return RecipeEvaluation(EvaluationState.NO_MATCH, legitimate, ("strong-legitimate-or-expected",))

        phishing = float(results["phishing_or_scam"])
        if phishing >= options["phishing_match_at"]:
            return RecipeEvaluation(EvaluationState.MATCH, phishing, ("strong-phishing-or-scam",))

        identity = float(results["identity_deception"])
        if identity >= options["identity_deception_at"] and action_safe >= options["provider_junk_support_at"]:
            return RecipeEvaluation(
                EvaluationState.MATCH,
                identity,
                ("identity-deception", "action-safe-corroboration"),
            )

        bulk = float(results["unsolicited_bulk"])
        if bulk >= options["unsolicited_bulk_at"] and action_safe >= options["action_safe_at"]:
            return RecipeEvaluation(
                EvaluationState.MATCH,
                bulk,
                ("unsolicited-bulk", "action-safe-corroboration"),
            )

        if (
            evidence.provider.trusted_spam
            and action_safe >= options["provider_junk_support_at"]
            and legitimate < 0.50
        ):
            return RecipeEvaluation(
                EvaluationState.MATCH,
                action_safe,
                ("trusted-provider-junk", "semantic-support"),
            )
        if evidence.provider.spam_marker or evidence.provider.subject_spam_marker:
            return RecipeEvaluation(
                EvaluationState.NO_MATCH,
                action_safe,
                ("provider-marker-needs-corroboration",),
            )
        return RecipeEvaluation(EvaluationState.NO_MATCH, None, ("insufficient-evidence",))
