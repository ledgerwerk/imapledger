from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image as PillowImage
from PIL import UnidentifiedImageError
from pyjev import BundleDecision, BundleResult, ChoiceResult, Image, NoulResult, ScoreResult

from imapledger.image_analysis import (
    IMAGE_ROLES,
    ImageAnalysisService,
    ImageImportancePolicy,
    ImagePreparer,
    ImageRecommendation,
)
from imapledger.message import MailImage, MailMessage


def _png_bytes(size: tuple[int, int] = (400, 300), *, mode: str = "RGB") -> bytes:
    output = BytesIO()
    PillowImage.new(mode, size, color=(30, 80, 120, 128) if mode == "RGBA" else (30, 80, 120)).save(
        output, format="PNG"
    )
    return output.getvalue()


def _image(index: int, data: bytes | None = None, *, classifiable: bool = True) -> MailImage:
    payload = data if data is not None else _png_bytes()
    return MailImage(
        index=index,
        content_type="image/png",
        filename="",
        content_id=f"cid-{index}",
        disposition="inline",
        data=payload,
        size_bytes=len(payload),
        classifiable=classifiable,
        skip_reason=None if classifiable else "image/gif is not supported by the visual analyzer",
    )


def _message(*images: MailImage) -> MailMessage:
    return MailMessage(
        uid=9,
        subject="Newsletter",
        sender="sender@example.org",
        recipients=(),
        date="",
        body="The email text",
        images=tuple(images),
    )


class _FakeJev:
    def __init__(self, shared: dict, *, images: bool) -> None:
        shared["image_options"].append(images)
        self.shared = shared

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return None

    def evaluate(self, decision, *, state):
        assert isinstance(decision, BundleDecision)
        self.shared["requests"].append((decision, state))
        call = len(self.shared["requests"])
        if call in self.shared["fail_calls"]:
            raise RuntimeError("private API response body")
        answers = {}
        for name in decision.questions:
            if name.endswith("_role"):
                role = "unknown" if self.shared["invalid"] == "role" else "product_or_offer"
                answers[name] = ChoiceResult(
                    value=role,
                    confidence=0.91,
                    probabilities={role: 0.91},
                    model="fake-model",
                    usage={},
                    raw={},
                )
            elif name.endswith("_importance"):
                value = 4.0 if self.shared["invalid"] == "score" else 1.2
                answers[name] = ScoreResult(
                    value=value,
                    confidence=0.86,
                    probabilities={1: 0.2, 2: 0.8},
                    legend={0: "decorative", 1: "supplementary", 2: "material", 3: "critical"},
                    model="fake-model",
                    usage={},
                    raw={},
                )
            else:
                if name.endswith("_text_insufficient"):
                    value = 0.18
                elif name.endswith("_actionable"):
                    value = float("nan") if self.shared["invalid"] == "probability" else 0.06
                else:
                    value = 0.92
                answers[name] = NoulResult(value=value, model="fake-model", usage={}, raw={})
        return BundleResult(
            answers=answers,
            model="fake-model",
            usage={},
            raw={},
            request_id=f"request-{call}",
        )


class _FakePreparer:
    def __init__(self, *, fail_indexes: set[int] | None = None) -> None:
        self.calls: list[int] = []
        self.fail_indexes = fail_indexes or set()

    def prepare(self, image: MailImage) -> bytes:
        self.calls.append(image.index)
        if image.index in self.fail_indexes:
            raise ValueError("private image detail")
        return image.data


def _fake_factory(shared: dict):
    return lambda *, images: _FakeJev(shared, images=images)


def _shared(*, fail_calls: set[int] | None = None, invalid: str | None = None) -> dict:
    return {"image_options": [], "requests": [], "fail_calls": fail_calls or set(), "invalid": invalid}


def test_service_uses_image_opt_in_structured_state_typed_bundle_and_propagates_metadata():
    shared = _shared()
    service = ImageAnalysisService(jev_factory=_fake_factory(shared), preparer=_FakePreparer())

    report = service.analyze(_message(_image(1)))

    assert shared["image_options"] == [True]
    decision, state = shared["requests"][0]
    assert set(decision.questions) == {
        "image_0001_role",
        "image_0001_importance",
        "image_0001_text_insufficient",
        "image_0001_actionable",
        "image_0001_interest_dependent",
    }
    assert state["email"] == {"subject": "Newsletter", "from": "sender@example.org", "body": "The email text"}
    assert isinstance(state["image"], Image)
    assert state["image"].data
    assert report.analyzed == 1
    assessment = report.assessments[0]
    assert assessment.role == "product_or_offer"
    assert assessment.recommendation is ImageRecommendation.OPTIONAL_IF_INTERESTED
    assert assessment.model == "fake-model"
    assert assessment.request_id == "request-1"


def test_recommendation_policy_covers_all_paths_and_threshold_edges():
    policy = ImageImportancePolicy()
    base = dict(
        role="decorative",
        importance_score=0.0,
        text_insufficient_probability=0.0,
        actionable_information_probability=0.0,
        interest_dependent_probability=0.0,
    )
    assert policy.recommend(**(base | {"actionable_information_probability": 0.85})) is ImageRecommendation.MUST_VIEW
    assert policy.recommend(**(base | {"text_insufficient_probability": 0.85})) is ImageRecommendation.MUST_VIEW
    assert policy.recommend(**(base | {"importance_score": 2.5})) is ImageRecommendation.MUST_VIEW
    assert (
        policy.recommend(**(base | {"role": "product_or_offer", "interest_dependent_probability": 0.75}))
        is ImageRecommendation.OPTIONAL_IF_INTERESTED
    )
    assert policy.recommend(**(base | {"importance_score": 1.5})) is ImageRecommendation.USEFUL
    assert policy.recommend(**(base | {"importance_score": 0.75})) is ImageRecommendation.SAFE_TO_IGNORE
    assert policy.recommend(**(base | {"text_insufficient_probability": 0.30})) is ImageRecommendation.REVIEW
    assert policy.recommend(**(base | {"interest_dependent_probability": 0.5})) is ImageRecommendation.SAFE_TO_IGNORE


def test_invalid_typed_result_and_non_finite_probability_skip_only_that_image():
    for invalid in ("role", "score", "probability"):
        shared = _shared(invalid=invalid)
        service = ImageAnalysisService(jev_factory=_fake_factory(shared), preparer=_FakePreparer())
        report = service.analyze(_message(_image(1)))
        assert report.analyzed == 0
        assert report.skipped == 1
        assert report.skipped_images[0].reason == "visual analysis unavailable"


def test_preparation_failure_api_failure_and_limits_are_isolated_and_bounded():
    shared = _shared(fail_calls={1})
    preparer = _FakePreparer(fail_indexes={2})
    service = ImageAnalysisService(
        jev_factory=_fake_factory(shared),
        preparer=preparer,
        max_embedded_images=2,
    )
    report = service.analyze(_message(_image(1), _image(2), _image(3), _image(4, classifiable=False)))

    assert len(shared["requests"]) == 1
    assert preparer.calls == [1, 2]
    assert report.embedded_total == 4
    assert report.remote_total == 0
    assert report.analyzed == 0
    assert report.skipped == 4
    assert [item.reason for item in report.skipped_images] == [
        "visual analysis unavailable",
        "image preparation failed",
        "analysis limit reached",
        "image/gif is not supported by the visual analyzer",
    ]
    assert "private" not in repr(report)


def test_byte_limit_skips_without_preparing_or_calling_pyjev():
    shared = _shared()
    preparer = _FakePreparer()
    service = ImageAnalysisService(
        jev_factory=_fake_factory(shared),
        preparer=preparer,
        max_image_bytes=1,
    )

    report = service.analyze(_message(_image(1)))

    assert report.skipped_images[0].reason == "image exceeds local byte limit"
    assert preparer.calls == []
    assert shared["requests"] == []


def test_image_preparer_normalizes_dimensions_orientation_alpha_and_bounds():
    preparer = ImagePreparer()
    small = _image(1, _png_bytes((1, 1)))
    normalized = PillowImage.open(BytesIO(preparer.prepare(small)))
    assert normalized.size == (280, 280)
    assert normalized.format == "JPEG"

    rotated = PillowImage.new("RGB", (400, 300), color=(30, 80, 120))
    exif = rotated.getexif()
    exif[274] = 6
    rotated_data = BytesIO()
    rotated.save(rotated_data, format="PNG", exif=exif)
    upright = PillowImage.open(BytesIO(preparer.prepare(_image(4, rotated_data.getvalue()))))
    assert upright.size == (300, 400)

    alpha = _image(2, _png_bytes((1800, 1200), mode="RGBA"))
    normalized_alpha = PillowImage.open(BytesIO(preparer.prepare(alpha)))
    assert normalized_alpha.format == "PNG"
    assert "A" in normalized_alpha.getbands()
    assert max(normalized_alpha.size) <= 1568
    assert normalized_alpha.width * normalized_alpha.height <= 2_458_624

    with pytest.raises(UnidentifiedImageError):
        preparer.prepare(_image(3, b"not an image"))
    with pytest.raises(ValueError, match="byte limit"):
        ImagePreparer(max_image_bytes=1).prepare(small)


def test_image_and_result_representations_do_not_expose_binary_payloads():
    image = _image(1)
    assert image.data.hex() not in repr(image)
    assert image.data.decode("latin1") not in repr(image)
    assert set(IMAGE_ROLES) >= {"product_or_offer", "financial_or_official_document"}
