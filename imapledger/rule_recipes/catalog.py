from __future__ import annotations

from collections.abc import Mapping

from ..routing_actions import RuleAction
from ..routing_models import RoutingRule, RuleType
from ..rules import RuleMatch
from .models import RuleRecipe, RuleRecipeSpec
from .spam import SPAM_RECIPE_SPEC, SpamRecipe

_STATIC_RECIPES = (
    RuleRecipeSpec(
        id="newsletter",
        title="Newsletter",
        category="Organization",
        summary="Route regular newsletters and mailing-list messages.",
        description="A semantic template for regular newsletters and mailing-list messages.",
        default_rule_id="newsletter",
        produces_type=RuleType.SEMANTIC,
        default_description="Regular newsletters and mailing-list messages",
    ),
    RuleRecipeSpec(
        id="receipt",
        title="Receipt / order confirmation",
        category="Commerce",
        summary="Recognize purchase receipts and order confirmations.",
        description="A semantic template for purchase receipts and order confirmations.",
        default_rule_id="receipt",
        produces_type=RuleType.SEMANTIC,
        default_description="Purchase receipts and order confirmations",
    ),
    RuleRecipeSpec(
        id="delivery-failure",
        title="Mail delivery failure",
        category="Delivery / system",
        summary="Recognize bounced messages and undeliverable notices.",
        description="A semantic template for mail delivery failure and undeliverable notices.",
        default_rule_id="delivery-failure",
        produces_type=RuleType.SEMANTIC,
        default_description="Mail delivery failures and undeliverable notices",
    ),
)

_SPAM_RECIPE = SpamRecipe()
_SPECS = {spec.id: spec for spec in (SPAM_RECIPE_SPEC, *_STATIC_RECIPES)}
_RUNTIME_RECIPES: dict[str, RuleRecipe] = {"spam": _SPAM_RECIPE}


def list_recipes(*, category: str | None = None, search: str | None = None) -> tuple[RuleRecipeSpec, ...]:
    recipes = tuple(_SPECS.values())
    if category is not None and category.casefold() != "all":
        recipes = tuple(recipe for recipe in recipes if recipe.category.casefold() == category.casefold())
    if search:
        term = search.casefold()
        recipes = tuple(
            recipe
            for recipe in recipes
            if term in " ".join(
                (recipe.id, recipe.title, recipe.category, recipe.summary, recipe.description)
            ).casefold()
        )
    return recipes


def get_recipe(recipe_id: str) -> RuleRecipeSpec:
    try:
        return _SPECS[recipe_id]
    except KeyError as exc:
        raise ValueError(f"unknown rule recipe: {recipe_id}") from exc


def get_runtime_recipe(recipe_id: str) -> RuleRecipe:
    try:
        return _RUNTIME_RECIPES[recipe_id]
    except KeyError as exc:
        raise ValueError(f"recipe has no runtime evaluator: {recipe_id}") from exc


def materialize_recipe(
    recipe_id: str,
    *,
    rule_id: str | None = None,
    action: RuleAction | str | None = None,
    destination: str | None = None,
    description: str | None = None,
    match_at: float | None = None,
    options: Mapping[str, object] | None = None,
    source_folders: tuple[str, ...] = (),
    match_any: tuple[RuleMatch, ...] = (),
) -> RoutingRule:
    spec = get_recipe(recipe_id)
    selected_action = RuleAction(action or spec.default_action)
    selected_id = rule_id or spec.default_rule_id
    selected_description = description if description is not None else spec.default_description
    selected_options: Mapping[str, object] = options or {}

    if spec.runtime_recipe is not None:
        runtime_recipe = get_runtime_recipe(spec.runtime_recipe)
        selected_options = runtime_recipe.validate_options(selected_options)
        return RoutingRule(
            id=selected_id,
            enabled=True,
            type=RuleType.RECIPE,
            action=selected_action,
            destination=destination,
            recipe=spec.runtime_recipe,
            options=selected_options,
            source_folders=source_folders,
            match_any=match_any,
        )

    if selected_options:
        raise ValueError(f"recipe {recipe_id} does not have runtime options")
    if spec.produces_type is RuleType.SEMANTIC and selected_description is None:
        raise ValueError(f"recipe {recipe_id} requires a semantic description")
    return RoutingRule(
        id=selected_id,
        enabled=True,
        type=spec.produces_type,
        action=selected_action,
        destination=destination,
        description=selected_description,
        match_at=match_at,
        source_folders=source_folders,
        match_any=match_any,
    )
