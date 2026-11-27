from __future__ import annotations

import pytest


@pytest.fixture
def advertising_description() -> str:
    lines = (
        "Classify an email as advertising if its primary purpose is to promote products, services, brands, "
        "subscriptions, events, or commercial offers, or to encourage a purchase or other commercial engagement.",
        "",
        "Include:",
        "",
        "- Promotional emails and marketing newsletters.",
        "- Discounts, coupons, special offers, and sales campaigns.",
        "- Product announcements and recommendations.",
        "- Personalized offers and targeted advertising.",
        "- Customer reactivation and abandoned shopping cart reminders.",
        "- Cross-selling, upselling, and subscription upgrade offers.",
        "- Sponsored content and affiliate marketing.",
        "- Unsolicited commercial offers and sales outreach.",
        "- Promotional invitations to webinars, events, or demonstrations.",
        "- Loyalty program promotions and referral campaigns.",
        "",
        "Classify these emails as advertising regardless of whether the recipient explicitly subscribed to them, "
        "has an existing customer relationship, or personally knows the sender.",
        "",
        "Exclude:",
        "",
        "- Invoices, receipts, and payment confirmations.",
        "- Order confirmations, shipping notifications, and delivery updates.",
        "- Security alerts and account-related notifications.",
        "- Contractual, legal, or mandatory service communications.",
        "- Personal correspondence.",
        "- Customer support conversations.",
        "- Subscription expiration and billing notifications without promotional intent.",
        "- Purely informational newsletters without commercial intent.",
        "",
        "Evaluate the subject and body of the email, regardless of language. If an email contains both "
        "transactional information and advertising, classify it according to its primary purpose.",
        "",
        "When uncertain, do not classify the email as advertising, to avoid filtering important correspondence.",
    )
    return "\n".join(lines)
