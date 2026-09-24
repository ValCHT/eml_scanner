"""TICKET-16 tests — bounded local Vision/QR capability (gate G7-B).

Everything here is OFFLINE and deterministic: controlled input fixtures only
(tests/fixtures/vision/), no network, no provider call, no attachment
execution, no fixture instruction ever executed. Provider responses used in
live contexts are NOT part of this file (capability smoke = scripts/smoke.py
vision); a mocked/stubbed answer is never presented as a runtime result.

The optional stack (Pillow, zxing-cpp) is installed in this environment; its
ABSENCE behavior is proven by the subprocess tests that block the imports
(docs/contracts.md §2.7.3): a text-only run must never import them.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import random
import subprocess
import sys
import textwrap
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from src.config import VisionToolConfig
from src.llm import LunaClient
from src.parsing import ParseLimits, parse_bytes
from src.prompts import ContextLimits, build_internal_envelope, build_internal_messages
from src.state import ParsedEmail
from src.vision import (
    VisionDependencyError,
    decode_qr,
    load_image_bytes,
    prepare_visual_bundle,
    prepare_visuals,
    qr_contract,
)

pytestmark = pytest.mark.g7b

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vision"

#: Exact frozen vision limits (configs/tools.yaml) — no other figures allowed.
VISION_LIMITS = VisionToolConfig(
    enabled=True,
    max_images=4,
    max_image_bytes=4194304,
    max_total_bytes=8388608,
    max_pixels=16000000,
)


def _fixture(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _eml_with_images(images: list[tuple[str, bytes]]) -> bytes:
    """Deterministic multipart/related email; inline images only."""

    parts: list[str] = [
        "From: Sender <sender@example.org>",
        "To: Analyst <analyst@example.test>",
        "Subject: controlled vision fixture",
        "MIME-Version: 1.0",
        'Content-Type: multipart/related; boundary="T16TESTBOUNDARY"',
        "",
        "--T16TESTBOUNDARY",
        "Content-Type: text/plain",
        "",
        "Body text.",
        "",
    ]
    for index, (subtype, payload_bytes) in enumerate(images):
        encoded = "\n".join(textwrap.wrap(base64.b64encode(payload_bytes).decode("ascii"), 76))
        parts += [
            "--T16TESTBOUNDARY",
            f"Content-Type: image/{subtype}",
            "Content-Transfer-Encoding: base64",
            f"Content-ID: <img{index}@example.org>",
            f'Content-Disposition: inline; filename="img{index}.{subtype}"',
            "",
            encoded,
            "",
        ]
    parts += ["--T16TESTBOUNDARY--", ""]
    return "\n".join(parts).encode("utf-8")


def _parsed_with(images: list[tuple[str, bytes]]) -> tuple[ParsedEmail, dict[str, bytes]]:
    eml = _eml_with_images(images)
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    assert isinstance(parsed, ParsedEmail), parsed
    return parsed, load_image_bytes(eml, parsed)


def _noise_png(width: int, height: int) -> bytes:
    """Deterministic pseudo-noise PNG (incompressible ⇒ size ≈ width*height)."""

    from PIL import Image

    raw = random.Random(0).randbytes(width * height)
    image = Image.frombuffer("L", (width, height), raw, "raw", "L", 0, 1)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def _solid_png(width: int, height: int) -> bytes:
    from PIL import Image

    buffer = io.BytesIO()
    Image.new("L", (width, height), 128).save(buffer, format="PNG")
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Image handling
# ---------------------------------------------------------------------------


def test_valid_png_is_staged_with_original_hash_and_provenance() -> None:
    banner = _fixture("benign_banner.png")
    parsed, image_bytes = _parsed_with([("png", banner)])
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=image_bytes, qr_enabled=False)
    assert len(prepared) == 1
    visual = prepared[0]
    assert visual.status == "supplied_to_model"
    assert visual.sha256 == hashlib.sha256(banner).hexdigest()
    assert visual.provenance == "INTERNE"
    assert (visual.width, visual.height) == (120, 40)
    assert visual.mime_type == "image/png"
    assert visual.part_id == "part_0003"
    assert visual.content_id == "img0@example.org"
    assert visual.local_ref == "mime:part_0003"


def test_valid_jpeg_is_staged_with_jpeg_data_uri_mime() -> None:
    jpeg = _fixture("benign_photo.jpeg")
    parsed, image_bytes = _parsed_with([("jpeg", jpeg)])
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=image_bytes)
    assert [visual.status for visual in prepared] == ["supplied_to_model"]
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=image_bytes)
    assert bundle.staged[0].data_mime_type == "image/jpeg"
    assert bundle.staged[0].sha256 == hashlib.sha256(jpeg).hexdigest()


def test_corrupt_png_becomes_unavailable_never_silently_discarded() -> None:
    corrupt = _fixture("corrupt.png")
    eml = _eml_with_images([("png", corrupt)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    image_bytes = load_image_bytes(eml, parsed)
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=image_bytes)
    assert len(prepared) == 1
    assert prepared[0].status == "unavailable"
    assert prepared[0].width is None and prepared[0].height is None
    assert prepared[0].sha256 == hashlib.sha256(corrupt).hexdigest()


def test_unsupported_gif_and_svg_never_decoded() -> None:
    from PIL import Image

    gif_buffer = io.BytesIO()
    Image.new("P", (16, 16), 0).save(gif_buffer, format="GIF")
    gif = gif_buffer.getvalue()
    svg = b"<svg xmlns='http://www.w3.org/2000/svg'><rect width='4' height='4'/></svg>"

    eml = _eml_with_images([("gif", gif), ("svg+xml", svg)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes={})
    assert [visual.status for visual in prepared] == ["unsupported", "unsupported"]
    assert all(visual.qr_payloads == [] for visual in prepared)
    assert decode_qr(gif) == []
    assert decode_qr(svg) == []


def test_mislabeled_gif_declared_png_is_unsupported() -> None:
    """Content is authoritative: declared image/png, actual GIF bytes."""

    from PIL import Image

    gif_buffer = io.BytesIO()
    Image.new("P", (16, 16), 3).save(gif_buffer, format="GIF")
    gif = gif_buffer.getvalue()
    eml = _eml_with_images([("png", gif)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    assert prepared[0].status == "unsupported"


def test_image_over_4mib_typed_over_limit_before_decode() -> None:
    big = _noise_png(2200, 2200)  # deterministic PNG > 4 MiB
    assert len(big) > 4194304
    eml = _eml_with_images([("png", big)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    assert prepared[0].status == "over_limit"
    assert prepared[0].width is None  # never decoded further


def test_decoded_pixels_over_16m_typed_over_limit() -> None:
    huge = _solid_png(5000, 3400)  # 17,000,000 declared pixels
    eml = _eml_with_images([("png", huge)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    assert prepared[0].status == "over_limit"


def test_more_than_four_images_caps_the_tail_deterministically() -> None:
    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner)] * 6)
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    assert len(parsed.images) == 6
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    statuses = [visual.status for visual in prepared]
    assert statuses == ["supplied_to_model"] * 4 + ["over_limit"] * 2
    again = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    assert [visual.model_dump_json() for visual in again] == [
        visual.model_dump_json() for visual in prepared
    ]


def test_cumulative_bytes_over_8mib_typed_over_limit() -> None:
    """Each image under 4 MiB, but the total over 8 MiB: typed, not dropped."""

    first = _noise_png(2800, 1000)  # ~2.8 MiB each
    second = _noise_png(2800, 1000)
    third = _noise_png(2800, 1000)
    assert len(first) < 4194304 and len(second) < 4194304 and len(third) < 4194304
    eml = _eml_with_images([("png", first), ("png", second), ("png", third)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    statuses = [visual.status for visual in prepared]
    assert statuses == ["supplied_to_model", "supplied_to_model", "over_limit"]


def test_deterministic_order_regardless_of_mapping_order() -> None:
    banner = _fixture("benign_banner.png")
    jpeg = _fixture("benign_photo.jpeg")
    eml = _eml_with_images([("png", banner), ("jpeg", jpeg)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    image_bytes = load_image_bytes(eml, parsed)
    first = prepare_visuals(parsed, VISION_LIMITS, image_bytes=image_bytes)
    reversed_mapping = dict(reversed(list(image_bytes.items())))
    second = prepare_visuals(parsed, VISION_LIMITS, image_bytes=reversed_mapping)
    assert [visual.model_dump_json() for visual in first] == [
        visual.model_dump_json() for visual in second
    ]


def test_parser_image_part_ids_are_reused_for_byte_extraction() -> None:
    banner = _fixture("benign_banner.png")
    jpeg = _fixture("benign_photo.jpeg")
    eml = _eml_with_images([("png", banner), ("jpeg", jpeg)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    extracted = load_image_bytes(eml, parsed)
    assert set(extracted.keys()) == {visual.part_id for visual in parsed.images}
    for visual in parsed.images:
        payload = extracted[visual.part_id]
        assert hashlib.sha256(payload).hexdigest() == visual.sha256


def test_metadata_only_when_no_bytes_are_supplied() -> None:
    eml = _eml_with_images([("png", _fixture("benign_banner.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=None)
    assert [visual.status for visual in prepared] == ["metadata_only"]
    assert prepared[0].sha256 == hashlib.sha256(_fixture("benign_banner.png")).hexdigest()
    assert prepared[0].width is None


def test_missing_bytes_for_a_declared_image_are_typed_unavailable() -> None:
    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner), ("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    assert isinstance(parsed, ParsedEmail)
    first_part_id = parsed.images[0].part_id
    only_first_part = {first_part_id: load_image_bytes(eml, parsed)[first_part_id]}
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=only_first_part)
    assert [visual.status for visual in prepared] == ["supplied_to_model", "unavailable"]


# ---------------------------------------------------------------------------
# Vision/QR independence (review PR #18): the two switches are separate
# ---------------------------------------------------------------------------


def test_vision_disabled_never_stages_pixels_even_with_bytes() -> None:
    """``vision.enabled=false``: metadata only, no pixel attached (text+QR base)."""

    banner = _fixture("benign_banner.png")
    parsed, image_bytes = _parsed_with([("png", banner)])
    disabled = VISION_LIMITS.model_copy(update={"enabled": False})
    bundle = prepare_visual_bundle(parsed, disabled, image_bytes=image_bytes)
    assert [visual.status for visual in bundle.visuals] == ["metadata_only"]
    assert bundle.staged == ()
    assert bundle.supplied_ids == []
    assert bundle.pixel_decoder_available is False
    # Bytes were available but no pixel may be attached: the text-only form
    # (and its empty SUPPLIED_VISUAL_IDS) stays byte-identical.
    messages, envelope = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert isinstance(messages[1]["content"], str)


def test_qr_only_mode_decodes_without_staging_any_pixel() -> None:
    """``text+QR``: vision disabled, QR enabled → exact payloads, zero pixels."""

    parsed, image_bytes = _parsed_with([("png", _fixture("qr_https.png"))])
    disabled = VISION_LIMITS.model_copy(update={"enabled": False})
    bundle = prepare_visual_bundle(
        parsed, disabled, image_bytes=image_bytes, qr_enabled=True
    )
    assert [visual.status for visual in bundle.visuals] == ["metadata_only"]
    assert [visual.qr_payloads for visual in bundle.visuals] == [
        ["https://qr.example.com/verify?id=42"]
    ]
    assert bundle.staged == ()
    assert bundle.supplied_ids == []
    assert bundle.qr_decode_requested is True
    links, observables, evidence = qr_contract(bundle.visuals)
    assert [link.role for link in links] == ["qr_url"]
    assert all(entry.provenance == "INTERNE" for entry in evidence)


def test_vision_only_mode_stages_without_executing_the_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``text+vision``: QR disabled → pixels staged, decoder never executed."""

    import src.vision as vision

    def _forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("QR decoder executed while QR_DECODE_ENABLED=false")

    monkeypatch.setattr(vision, "decode_qr", _forbidden)
    banner = _fixture("benign_banner.png")
    parsed, image_bytes = _parsed_with([("png", banner)])
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=image_bytes, qr_enabled=False
    )
    assert [visual.status for visual in bundle.visuals] == ["supplied_to_model"]
    assert [visual.qr_payloads for visual in bundle.visuals] == [[]]
    assert bundle.staged and bundle.staged[0].visual_id == parsed.images[0].id


def test_derived_sha256_is_the_hash_of_the_exact_staged_bytes() -> None:
    """The staged hash is computed from the bytes, never copied from the parent."""

    banner = _fixture("benign_banner.png")
    parsed, image_bytes = _parsed_with([("png", banner)])
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=image_bytes)
    staged = bundle.staged[0]
    assert staged.derived_sha256 == hashlib.sha256(banner).hexdigest()
    assert staged.derived_sha256 == staged.sha256 == parsed.images[0].sha256
    assert base64.b64decode(staged.data_uri.split(",", 1)[1]) == banner


def test_wrong_bytes_for_a_part_are_refused_never_staged() -> None:
    """A wrong ``part_id → bytes`` association must not send foreign pixels."""

    banner = _fixture("benign_banner.png")
    jpeg = _fixture("benign_photo.jpeg")
    eml = _eml_with_images([("png", banner), ("jpeg", jpeg)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    assert isinstance(parsed, ParsedEmail)
    extracted = load_image_bytes(eml, parsed)
    tampered = dict(extracted)
    tampered[parsed.images[0].part_id] = jpeg  # valid JPEG, wrong visual
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=tampered)
    assert bundle.visuals[0].status == "unavailable"
    assert bundle.visuals[0].sha256 == hashlib.sha256(banner).hexdigest()
    assert [staged.visual_id for staged in bundle.staged] == [parsed.images[1].id]
    assert all(
        staged.derived_sha256 == staged.sha256 for staged in bundle.staged
    )


# ---------------------------------------------------------------------------
# QR decoding (local only, deterministic)
# ---------------------------------------------------------------------------


def test_decode_qr_exact_payload() -> None:
    assert decode_qr(_fixture("qr_text.png")) == ["SOC-POC-CASE-0042-BENIGN"]


def test_decode_qr_deduplicates_exact_duplicates_stably() -> None:
    assert decode_qr(_fixture("qr_dup.png")) == ["SOC-POC-DUP-0042"]


def test_decode_qr_without_qr_or_corrupt_bytes_is_typed_absence() -> None:
    assert decode_qr(_fixture("benign_banner.png")) == []
    assert decode_qr(_fixture("corrupt.png")) == []


def test_missing_decoder_is_explicit_not_a_silent_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import src.vision as vision

    eml = _eml_with_images([("png", _fixture("qr_https.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    image_bytes = load_image_bytes(eml, parsed)

    monkeypatch.setitem(sys.modules, "zxingcpp", None)
    with pytest.raises(VisionDependencyError, match="zxing-cpp"):
        decode_qr(_fixture("qr_text.png"))
    # prepare_visuals degrades typed (qr payloads empty), never crashes.
    prepared = prepare_visuals(parsed, VISION_LIMITS, image_bytes=image_bytes, qr_enabled=True)
    assert [visual.status for visual in prepared] == ["supplied_to_model"]
    assert all(visual.qr_payloads == [] for visual in prepared)


def test_qr_https_url_contract_role_and_provenance() -> None:
    eml = _eml_with_images([("png", _fixture("qr_https.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    assert [visual.qr_payloads for visual in prepared] == [
        ["https://qr.example.com/verify?id=42"]
    ]
    links, observables, evidence = qr_contract(prepared)
    assert [(link.role, link.raw_value, link.normalized_value, link.hostname) for link in links] == [
        ("qr_url", "https://qr.example.com/verify?id=42", "https://qr.example.com/verify?id=42", "qr.example.com")
    ]
    assert all(obs.provenance == "INTERNE" and obs.roles == ["link_target"] for obs in observables)
    assert all(entry.provenance == "INTERNE" for entry in evidence)
    predicates = {entry.predicate for entry in evidence}
    assert predicates == {"qr_payload", "url_found"}
    # The exact payload is preserved verbatim everywhere.
    assert all(entry.value == "https://qr.example.com/verify?id=42" for entry in evidence if entry.value)


def test_qr_http_url_contract() -> None:
    eml = _eml_with_images([("png", _fixture("qr_http.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    links, observables, evidence = qr_contract(prepared)
    assert [(link.role, link.raw_value) for link in links] == [
        ("qr_url", "http://qr.example.org/bounce?id=42")
    ]
    assert all(obs.provenance == "INTERNE" for obs in observables)
    assert {entry.predicate for entry in evidence} == {"qr_payload", "url_found"}


def test_qr_non_url_payload_stays_text_evidence_never_a_url() -> None:
    eml = _eml_with_images([("png", _fixture("qr_text.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    prepared = prepare_visuals(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    links, observables, evidence = qr_contract(prepared)
    assert links == [] and observables == []
    assert [(entry.predicate, entry.value, entry.provenance) for entry in evidence] == [
        ("qr_payload", "SOC-POC-CASE-0042-BENIGN", "INTERNE")
    ]


def test_qr_url_never_fetched_and_never_submitted(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def _forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("network/shell side effect attempted during QR handling")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    monkeypatch.setattr(socket.socket, "connect", _forbidden, raising=False)
    monkeypatch.setattr(socket, "create_connection", _forbidden, raising=False)
    monkeypatch.setattr(subprocess.Popen, "__init__", _forbidden, raising=False)

    for name in ("qr_https.png", "qr_http.png", "qr_text.png"):
        eml = _eml_with_images([("png", _fixture(name))])
        parsed = parse_bytes(eml, "rfc822", ParseLimits())
        prepared = prepare_visuals(
            parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
        )
        links, observables, evidence = qr_contract(prepared)
        if name != "qr_text.png":
            assert links and observables
        else:
            assert not links and not observables


# ---------------------------------------------------------------------------
# Optional dependencies: disabled modes (subprocess proofs)
# ---------------------------------------------------------------------------


def _import_blocker(tmp_path: Any, block_pillow: bool = False) -> Any:
    """A directory whose PIL/zxingcpp imports always raise ImportError."""

    blocker = tmp_path / "blocked_imports"
    blocker.mkdir(exist_ok=True)
    if block_pillow:
        (blocker / "PIL").mkdir(exist_ok=True)
        (blocker / "PIL" / "__init__.py").write_text(
            'raise ImportError("optional vision stack blocked by test")\n', encoding="utf-8"
        )
    (blocker / "zxingcpp.py").write_text(
        'raise ImportError("optional QR decoder blocked by test")\n', encoding="utf-8"
    )
    return blocker


def _run_python(project_root: Path, code: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=project_root,
        shell=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def _blocked_env(project_root: Path, blocker: Any) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": f"{blocker}{os.pathsep}{project_root}",
    }


def test_text_only_path_never_imports_the_optional_stack(
    tmp_path: Any, project_root: Path
) -> None:
    """MODEL_SUPPORTS_VISION=false: text-only analysis without PIL/zxingcpp."""

    code = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, r"{project_root}")
        from pathlib import Path

        from src.config import VisionToolConfig
        from src.parsing import ParseLimits, parse_bytes
        from src.prompts import ContextLimits, build_internal_messages
        from src.vision import prepare_visuals

        limits = VisionToolConfig(
            enabled=False, max_images=4, max_image_bytes=4194304,
            max_total_bytes=8388608, max_pixels=16000000,
        )
        eml = Path(r"{FIXTURES / 'benign_image.eml'}").read_bytes()
        parsed = parse_bytes(eml, "rfc822", ParseLimits())
        prepared = prepare_visuals(parsed, limits)
        assert [visual.status for visual in prepared] == ["metadata_only"]
        messages, envelope = build_internal_messages(parsed, ContextLimits())
        assert envelope["SUPPLIED_VISUAL_IDS"] == []
        assert isinstance(messages[1]["content"], str)
        assert "PIL" not in sys.modules, "Pillow imported by the text-only path"
        assert "zxingcpp" not in sys.modules, "zxing-cpp imported by the text-only path"
        print("OK")
        """
    )
    proc = _run_python(
        project_root,
        code,
        _blocked_env(project_root, _import_blocker(tmp_path, block_pillow=True)),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_qr_disabled_never_executes_the_decoder(tmp_path: Any, project_root: Path) -> None:
    """QR decode disabled: pixels still staged, decoder never imported."""

    code = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, r"{project_root}")
        from pathlib import Path

        from src.config import VisionToolConfig
        from src.parsing import ParseLimits, parse_bytes
        from src.vision import load_image_bytes, prepare_visuals

        limits = VisionToolConfig(
            enabled=True, max_images=4, max_image_bytes=4194304,
            max_total_bytes=8388608, max_pixels=16000000,
        )
        eml = Path(r"{FIXTURES / 'benign_image.eml'}").read_bytes()
        parsed = parse_bytes(eml, "rfc822", ParseLimits())
        prepared = prepare_visuals(
            parsed, limits,
            image_bytes=load_image_bytes(eml, parsed),
            qr_enabled=False,
        )
        assert [visual.status for visual in prepared] == ["supplied_to_model"]
        assert all(visual.qr_payloads == [] for visual in prepared)
        assert "zxingcpp" not in sys.modules, "QR decoding executed while disabled"
        print("OK")
        """
    )
    proc = _run_python(
        project_root,
        code,
        _blocked_env(project_root, _import_blocker(tmp_path)),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_qr_enabled_without_decoder_degrades_typed(
    tmp_path: Any, project_root: Path
) -> None:
    code = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, r"{project_root}")
        from pathlib import Path

        from src.config import VisionToolConfig
        from src.parsing import ParseLimits, parse_bytes
        from src.vision import load_image_bytes, prepare_visuals

        limits = VisionToolConfig(
            enabled=True, max_images=4, max_image_bytes=4194304,
            max_total_bytes=8388608, max_pixels=16000000,
        )
        eml = Path(r"{FIXTURES / 'benign_image.eml'}").read_bytes()
        parsed = parse_bytes(eml, "rfc822", ParseLimits())
        prepared = prepare_visuals(
            parsed, limits,
            image_bytes=load_image_bytes(eml, parsed),
            qr_enabled=True,
        )
        assert [visual.status for visual in prepared] == ["supplied_to_model"]
        assert all(visual.qr_payloads == [] for visual in prepared)
        assert "zxingcpp" not in sys.modules
        print("OK")
        """
    )
    proc = _run_python(
        project_root,
        code,
        _blocked_env(project_root, _import_blocker(tmp_path)),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def test_vision_disabled_with_bytes_never_imports_the_optional_stack(
    tmp_path: Any, project_root: Path
) -> None:
    """``vision.enabled=false`` with bytes loaded: metadata only, no PIL/zxingcpp."""

    code = textwrap.dedent(
        f"""
        import sys
        sys.path.insert(0, r"{project_root}")
        from pathlib import Path

        from src.config import VisionToolConfig
        from src.parsing import ParseLimits, parse_bytes
        from src.vision import load_image_bytes, prepare_visuals

        limits = VisionToolConfig(
            enabled=False, max_images=4, max_image_bytes=4194304,
            max_total_bytes=8388608, max_pixels=16000000,
        )
        eml = Path(r"{FIXTURES / 'benign_image.eml'}").read_bytes()
        parsed = parse_bytes(eml, "rfc822", ParseLimits())
        image_bytes = load_image_bytes(eml, parsed)
        prepared = prepare_visuals(
            parsed, limits, image_bytes=image_bytes, qr_enabled=False
        )
        assert [visual.status for visual in prepared] == ["metadata_only"]
        assert all(visual.qr_payloads == [] for visual in prepared)
        assert "PIL" not in sys.modules, "Pillow imported while vision is disabled"
        assert "zxingcpp" not in sys.modules, "zxing-cpp imported while QR is disabled"
        print("OK")
        """
    )
    proc = _run_python(
        project_root,
        code,
        _blocked_env(project_root, _import_blocker(tmp_path, block_pillow=True)),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout


def _load_smoke_module() -> Any:
    """Import ``scripts/smoke.py`` without running its CLI."""

    import importlib.util
    import sys

    path = Path(__file__).resolve().parent.parent / "scripts" / "smoke.py"
    spec = importlib.util.spec_from_file_location("smoke_script", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["smoke_script"] = module
    spec.loader.exec_module(module)
    return module


def test_smoke_vision_schema_is_the_frozen_assessment_schema(project_root: Path) -> None:
    """``smoke.py vision`` must send the real INTERNAL schema (review PR #18)."""

    smoke = _load_smoke_module()
    schema = smoke._smoke_vision_schema()
    frozen = json.loads(
        (project_root / "schemas" / "assessment.schema.json").read_text(encoding="utf-8")
    )
    assert schema == frozen


def test_smoke_vision_receipt_recovers_the_real_attempt_metadata(tmp_path: Path) -> None:
    """TICKET-19D §1: the receipt reads the files ``LunaClient`` really writes.

    The T16 receipt globbed ``internal_attempt_*_response_meta.json`` while the
    client writes ``attempt_<n>_response_meta.json``, so a real response hash
    and size were dropped. Recovery must be exact: no network, no raw body,
    no invented value.
    """

    smoke = _load_smoke_module()
    capture = tmp_path / "capture"
    capture.mkdir()
    response = b'{"choices": []}'
    (capture / "attempt_1_response_meta.json").write_text(
        json.dumps(
            {
                "response_sha256": hashlib.sha256(response).hexdigest(),
                "response_bytes": len(response),
                "returned_model": "Qwen/Qwen3.8-27B",
                "usage": {"input_tokens": 12, "output_tokens": 3},
            }
        ),
        encoding="utf-8",
    )
    (capture / "internal_attempt_1.input_audit.json").write_text(
        json.dumps({"untrusted_email_sha256": "a" * 64}), encoding="utf-8"
    )

    facts = smoke._smoke_vision_facts(capture, 1)
    meta = facts["meta"]
    assert meta["response_sha256"] == hashlib.sha256(response).hexdigest()
    assert meta["response_bytes"] == len(response)
    assert facts["audit"]["untrusted_email_sha256"] == "a" * 64
    assert facts["errors"] == []


def test_smoke_vision_receipt_is_null_without_metadata(tmp_path: Path) -> None:
    """TICKET-19D §1: no attempt metadata -> null/null, never an invented value."""

    smoke = _load_smoke_module()
    capture = tmp_path / "capture"
    capture.mkdir()

    no_attempt = smoke._smoke_vision_facts(capture, 0)
    assert no_attempt["meta"].get("response_sha256") is None
    assert no_attempt["meta"].get("response_bytes") is None

    # An attempt number without a produced metadata file stays null as well.
    missing_file = smoke._smoke_vision_facts(capture, 1)
    assert missing_file["meta"].get("response_sha256") is None
    assert missing_file["meta"].get("response_bytes") is None
    assert missing_file["errors"] == []


# ---------------------------------------------------------------------------
# LLM multipart envelope (docs/tickets/TICKET-16.md §12 contract)
# ---------------------------------------------------------------------------


def test_zero_supplied_pixels_keep_the_text_only_form() -> None:
    eml = _eml_with_images([("png", _fixture("benign_banner.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    messages, envelope = build_internal_messages(parsed, ContextLimits())
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert isinstance(messages[1]["content"], str)
    assert "data:image" not in json.dumps(envelope)


def test_one_staged_image_supplies_exactly_one_id_and_real_pixels() -> None:
    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    assert len(bundle.staged) == 1

    messages, envelope = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    assert envelope["SUPPLIED_VISUAL_IDS"] == bundle.supplied_ids
    assert envelope["SUPPLIED_VISUAL_IDS"] == [parsed.images[0].id]
    user_content = messages[1]["content"]
    assert isinstance(user_content, list)
    assert [part["type"] for part in user_content] == ["text", "image_url"]
    data_uri = user_content[1]["image_url"]["url"]
    assert data_uri.startswith("data:image/png;base64,")
    assert base64.b64decode(data_uri.split(",", 1)[1]) == banner


def test_no_visual_id_without_pixels_no_pixels_without_id() -> None:
    eml = _eml_with_images([("png", _fixture("benign_banner.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    real_id = parsed.images[0].id

    class _Stranger:
        visual_id = "vis_stranger"
        data_mime_type = "image/png"
        data_uri = "data:image/png;base64,AAAA"

    with pytest.raises(ValueError, match="not a VisualEvidence of this email"):
        build_internal_envelope(parsed, ContextLimits(), [_Stranger()])

    class _Incomplete:
        visual_id = real_id

    with pytest.raises(ValueError, match="StagedVisual"):
        build_internal_envelope(parsed, ContextLimits(), [_Incomplete()])


def test_invalid_data_uri_forms_are_refused_before_any_call() -> None:
    eml = _eml_with_images([("png", _fixture("benign_banner.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    real_id = parsed.images[0].id

    class _Gif:
        visual_id = real_id
        data_mime_type = "image/gif"
        data_uri = "data:image/gif;base64,AAAA"

    with pytest.raises(ValueError, match="PNG/JPEG"):
        build_internal_envelope(parsed, ContextLimits(), [_Gif()])

    class _Remote:
        visual_id = real_id
        data_mime_type = "image/png"
        data_uri = "https://remote.example.org/image.png"

    with pytest.raises(ValueError, match="data:image/png;base64,"):
        build_internal_envelope(parsed, ContextLimits(), [_Remote()])


def test_system_prompt_unchanged_and_pixels_stay_user_content() -> None:
    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    text_only = build_internal_messages(parsed, ContextLimits())[0]
    multimodal = build_internal_messages(parsed, ContextLimits(), bundle.staged)[0]
    # The system message is EXACTLY the same: no image content promoted there.
    assert text_only[0] == multimodal[0]
    assert isinstance(multimodal[1]["content"], list)
    assert multimodal[1]["content"][0]["type"] == "text"
    assert multimodal[1]["content"][1]["type"] == "image_url"


def test_no_local_path_or_remote_scheme_in_the_request() -> None:
    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))
    messages, _ = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    serialized = json.dumps(messages, ensure_ascii=False)
    assert str(FIXTURES) not in serialized
    for forbidden in ("http://", "https://", "file://"):
        assert forbidden not in serialized


def test_visual_count_sent_counts_real_pixel_blocks() -> None:
    from src.llm import _json_bytes

    banner = _fixture("benign_banner.png")
    eml = _eml_with_images([("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed))

    # Text-only form: user content is a string → zero pixel blocks.
    text_only_messages, _ = build_internal_messages(parsed, ContextLimits())
    text_body = _json_bytes({"model": "test/model", "messages": text_only_messages})
    assert LunaClient.compute_input_audit(text_body, "final")["visual_count_sent"] == 0

    # Multimodal form: exactly one image block per staged visual.
    messages, _ = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    body = _json_bytes({"model": "test/model", "messages": messages})
    audit = LunaClient.compute_input_audit(body, "final")
    assert audit["visual_count_sent"] == len(bundle.staged) == 1


# ---------------------------------------------------------------------------
# Security: image/QR content is untrusted data, never instructions
# ---------------------------------------------------------------------------


def test_prompt_injection_image_stays_evidence_only() -> None:
    banner = _fixture("prompt_injection_image.png")
    eml = _eml_with_images([("png", banner)])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    prepared = bundle.visuals
    assert prepared[0].status == "supplied_to_model"
    # Text inside pixels creates NO QR payload, NO link, NO observable.
    assert prepared[0].qr_payloads == []
    links, observables, evidence = qr_contract(prepared)
    assert links == [] and observables == []

    messages, envelope = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    text_part = messages[1]["content"][0]["text"]
    assert "IGNORE SYSTEM PROMPT" not in text_part
    assert "IGNORE SYSTEM PROMPT" not in messages[0]["content"]
    # The pixels themselves are still really attached to the call.
    assert messages[1]["content"][1]["type"] == "image_url"


def test_no_shell_browser_or_http_side_effect_in_the_whole_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket

    def _no_side_effect(*args: Any, **kwargs: Any) -> None:
        pytest.fail("shell/browser/HTTP side effect attempted")

    monkeypatch.setattr(urllib.request, "urlopen", _no_side_effect)
    monkeypatch.setattr(socket.socket, "connect", _no_side_effect, raising=False)
    monkeypatch.setattr(socket, "create_connection", _no_side_effect, raising=False)
    monkeypatch.setattr(subprocess.Popen, "__init__", _no_side_effect, raising=False)

    for name in ("qr_https.png", "qr_http.png", "qr_text.png", "benign_banner.png", "corrupt.png"):
        decode_qr(_fixture(name))
    eml = _eml_with_images([("png", _fixture("qr_https.png"))])
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    qr_contract(bundle.visuals)


# ---------------------------------------------------------------------------
# TICKET-20 — HTML-embedded images through the EXISTING Vision pipeline
#
# Same module, same limits, same QR decoder, same envelope contract: the
# only difference is where the bytes came from (an <img src="data:...">
# blob decoded by the parser instead of a MIME part). Offline only.
# ---------------------------------------------------------------------------


def _eml_with_html(html_body: str) -> bytes:
    return (
        "From: Sender <sender@example.org>\r\n"
        "To: Analyst <analyst@example.test>\r\n"
        "Subject: controlled T20 html fixture\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: text/html; charset="utf-8"\r\n'
        "\r\n" + html_body
    ).encode("utf-8")


def _parsed_html(html_body: str) -> tuple[ParsedEmail, bytes]:
    eml = _eml_with_html(html_body)
    parsed = parse_bytes(eml, "rfc822", ParseLimits())
    assert isinstance(parsed, ParsedEmail), parsed
    return parsed, eml


def _embedded_src(mime: str, data: bytes) -> str:
    return f'src="data:{mime};base64,{base64.b64encode(data).decode("ascii")}"'


def test_t20_09_embedded_png_staged_with_exact_pixels_and_id() -> None:
    """T20-09: Vision ON really attaches the embedded pixels (one exact id)."""

    png = _fixture("benign_banner.png")
    parsed, eml = _parsed_html(f'<img alt="b" {_embedded_src("image/png", png)}>')
    assert len(parsed.images) == 1
    visual_id = parsed.images[0].id
    image_bytes = load_image_bytes(eml, parsed)
    assert set(image_bytes) == {parsed.images[0].part_id}
    bundle = prepare_visual_bundle(parsed, VISION_LIMITS, image_bytes=image_bytes)
    assert [visual.status for visual in bundle.visuals] == ["supplied_to_model"]
    staged = bundle.staged[0]
    assert staged.visual_id == visual_id
    assert staged.derived_sha256 == staged.sha256 == hashlib.sha256(png).hexdigest()
    assert base64.b64decode(staged.data_uri.split(",", 1)[1]) == png

    messages, envelope = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    assert envelope["SUPPLIED_VISUAL_IDS"] == [visual_id]
    user_content = messages[1]["content"]
    assert isinstance(user_content, list)
    assert [part["type"] for part in user_content] == ["text", "image_url"]
    data_uri = user_content[1]["image_url"]["url"]
    assert data_uri.startswith("data:image/png;base64,")
    assert base64.b64decode(data_uri.split(",", 1)[1]) == png


def test_t20_10_vision_off_keeps_placeholder_and_sends_no_pixel() -> None:
    """T20-10: no image_url, SUPPLIED_VISUAL_IDS=[], HTML cleaned anyway."""

    png = _fixture("benign_banner.png")
    payload = base64.b64encode(png).decode("ascii")
    parsed, eml = _parsed_html(f'<img {_embedded_src("image/png", png)}>')
    disabled = VISION_LIMITS.model_copy(update={"enabled": False})
    bundle = prepare_visual_bundle(
        parsed, disabled, image_bytes=load_image_bytes(eml, parsed)
    )
    assert [visual.status for visual in bundle.visuals] == ["metadata_only"]
    assert bundle.staged == ()
    assert bundle.supplied_ids == []

    messages, envelope = build_internal_messages(parsed, ContextLimits())
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert isinstance(messages[1]["content"], str)  # text-only form
    serialized = json.dumps(envelope, ensure_ascii=False)
    assert payload not in serialized  # no Base64 blob in the envelope
    assert "[embedded-image:" in serialized  # compact deterministic reference
    assert "data:image" not in json.dumps(messages)


def test_t20_08_qr_in_embedded_html_image_reuses_the_existing_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T20-08: the same decode_qr / qr_contract path, zero network."""

    import socket

    def _forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("network/shell side effect attempted during embedded QR handling")

    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    monkeypatch.setattr(socket.socket, "connect", _forbidden, raising=False)
    monkeypatch.setattr(socket, "create_connection", _forbidden, raising=False)
    monkeypatch.setattr(subprocess.Popen, "__init__", _forbidden, raising=False)

    parsed, eml = _parsed_html(f'<img {_embedded_src("image/png", _fixture("qr_https.png"))}>')
    disabled = VISION_LIMITS.model_copy(update={"enabled": False})
    bundle = prepare_visual_bundle(
        parsed, disabled, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    assert [visual.qr_payloads for visual in bundle.visuals] == [
        ["https://qr.example.com/verify?id=42"]
    ]
    assert bundle.staged == ()  # text+QR: payloads without any pixel
    links, observables, evidence = qr_contract(bundle.visuals)
    assert [link.role for link in links] == ["qr_url"]
    assert [link.raw_value for link in links] == ["https://qr.example.com/verify?id=42"]
    assert all(observable.provenance == "INTERNE" for observable in observables)
    assert {entry.predicate for entry in evidence} == {"qr_payload", "url_found"}
    assert all(entry.provenance == "INTERNE" for entry in evidence)


def test_t20_06_embedded_image_over_4mib_is_over_limit_without_pixels() -> None:
    """T20-06: the frozen 4 MiB per-image limit applies before any decode."""

    big = b"\x89PNG\r\n\x1a\n" + b"x" * 4_200_000  # declared PNG, over 4 MiB
    parsed, eml = _parsed_html(f'<img {_embedded_src("image/png", big)}>')
    assert len(parsed.images) == 1  # parser metadata-only state, bounded
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed)
    )
    assert [visual.status for visual in bundle.visuals] == ["over_limit"]
    assert bundle.staged == ()
    assert bundle.supplied_ids == []


def test_t20_07_embedded_images_keep_document_order_and_vision_cap() -> None:
    """T20-07: HTML order preserved; the existing max_images cap still applies."""

    png = _fixture("benign_banner.png")
    jpeg = _fixture("benign_photo.jpeg")
    html = "".join(
        f'<img {_embedded_src("image/png" if index % 2 == 0 else "image/jpeg", png if index % 2 == 0 else jpeg)}>'
        for index in range(5)
    )
    parsed, eml = _parsed_html(html)
    assert [visual.part_id for visual in parsed.images] == [
        f"part_0001:img{index}" for index in range(5)
    ]
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed)
    )
    assert [visual.status for visual in bundle.visuals] == [
        "supplied_to_model",
        "supplied_to_model",
        "supplied_to_model",
        "supplied_to_model",
        "over_limit",
    ]
    assert [staged.visual_id for staged in bundle.staged] == [
        visual.id for visual in parsed.images[:4]
    ]


def test_t20_cap_never_leaks_supported_base64_into_the_envelope() -> None:
    """PR #22-1: beyond the parser cap, no supported blob stays as text."""

    tiny_png = _solid_png(1, 1)  # valid, small, decodable
    html = "".join(f'<img {_embedded_src("image/png", tiny_png)}>' for _ in range(65))
    parsed, eml = _parsed_html(html)
    assert len(parsed.images) == 64  # extraction bounded
    assert "max_html_embedded_images" in parsed.content_limits
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed)
    )
    assert len(bundle.staged) == VISION_LIMITS.max_images  # staged pixels bounded
    _, envelope = build_internal_messages(parsed, ContextLimits())
    serialized = json.dumps(envelope, ensure_ascii=False)
    assert "base64," not in serialized  # no supported blob in the LLM context
    assert "data:image" not in serialized
    assert serialized.count("[embedded-image:over-limit]") == 1
    assert serialized.count("[embedded-image:vis_") == 64


def test_t20_11_embedded_injection_image_is_pixels_only_never_ocr() -> None:
    """T20-11: hostile pixels are staged as pixels; no OCR, no instruction."""

    hostile = _fixture("prompt_injection_image.png")
    parsed, eml = _parsed_html(f'<img {_embedded_src("image/png", hostile)}>')
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed), qr_enabled=True
    )
    assert [visual.status for visual in bundle.visuals] == ["supplied_to_model"]
    assert bundle.staged[0].visual_id == parsed.images[0].id
    assert parsed.text_parts == []  # no text was invented from the pixels

    messages, envelope = build_internal_messages(parsed, ContextLimits(), bundle.staged)
    assert "IGNORE SYSTEM PROMPT" not in messages[0]["content"]
    assert "IGNORE SYSTEM PROMPT" not in messages[1]["content"][0]["text"]
    assert "IGNORE SYSTEM PROMPT" not in json.dumps(envelope)
    # The pixels themselves are still really attached to the call.
    assert messages[1]["content"][1]["type"] == "image_url"


def test_t20_05_embedded_forbidden_type_never_supplied_to_model() -> None:
    """T20-05: an embedded SVG never reaches the model as an image."""

    svg = b"<svg xmlns='http://www.w3.org/2000/svg'><rect width='4' height='4'/></svg>"
    parsed, eml = _parsed_html(f'<img {_embedded_src("image/svg+xml", svg)}>')
    assert parsed.images == []
    bundle = prepare_visual_bundle(
        parsed, VISION_LIMITS, image_bytes=load_image_bytes(eml, parsed)
    )
    assert bundle.visuals == []
    assert bundle.staged == ()
    messages, envelope = build_internal_messages(parsed, ContextLimits())
    assert envelope["SUPPLIED_VISUAL_IDS"] == []
    assert "image_url" not in json.dumps(messages)
