"""TICKET-15 RAG tests — public-only local Chroma (gate G7-A, non-live).

Coverage of docs/tickets/TICKET-15.md TESTS REQUIRED (offline part):

- source contract: private, gold (dev/test split), unconfirmed and
  malformed cases are refused — they cannot even be constructed;
- metadata contract: a retrieved neighbour keeps the FULL public record
  (label, analyst rationale, validation reference); a changed rationale
  under an existing case_id is a divergent replay, refused;
- real corpus: public-only artifact + gold_dev isolation + the sealed test
  aggregate; gold_test.jsonl is NEVER opened before T19E (tracked by test,
  the RAG/test disjointness is inherited from the T13 split);
- local Chroma storage: add/search/clear, idempotent re-add, one case per
  family, max_cases, oversized excerpt refusal;
- retrieval: distance threshold (never a forced neighbour), exclusion of
  the current message's family/duplicate/campaign groups, deterministic k
  and ``(distance, case_id)`` ordering;
- persistence across adapter instances; embedding fingerprint frozen in
  the collection metadata and verified on every open; a missing chromadb
  dependency is a typed refusal, never a silent skip;
- disabled mode: module import, the factory and the pipeline import
  NEITHER chromadb NOR the ONNX weights (proven in subprocesses);
- graph wiring: node_rag_lookup query/exclusions/k, typed failures, V15
  current-group propagation, and a FULL controlled graph run over a real
  temporary public index (fake Luna/tools — never provider observations).

Offline storage tests use the deterministic stub embedder so the real
frozen ONNX model is never downloaded by tests; the real embedding is
validated by ``python scripts/manage_rag.py add`` (the ticket command).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from src.config import (
    EgressConfig,
    GateConfig,
    PolicyConfig,
    RagToolConfig,
    ToolsConfig,
    load_settings,
    load_yaml_config,
)
from src.graph import (
    Services,
    build_graph,
    build_services,
    node_rag_lookup,
)
from src.state import (
    CallRecord,
    EmailTriageState,
    Observable,
    ParsedEmail,
    RagCase,
    TextPart,
    ToolResult,
    new_state,
)
from src.tools.rag import (
    EMBEDDING_MODEL_NAME,
    RagAdapter,
    RagEmbeddingModel,
    RagIndexError,
    RagModelError,
    RagSourceCase,
    RagSourceError,
    RagUnavailableError,
    create_rag_adapter_if_enabled,
    rag_query_from_parsed,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.g7a


# ---------------------------------------------------------------------------
# Controlled helpers (offline stubs; no network, no provider observations)
# ---------------------------------------------------------------------------


@pytest.fixture()
def chromadb_or_skip() -> None:
    """Local-Chroma tests need the [rag] extra; skip cleanly without it.

    check_gate refuses skipped mandatory tests, so G7-A PASS stays
    impossible without the extra installed — a skip can never fake a PASS.
    """

    pytest.importorskip("chromadb")


def _stub_embedder(fingerprint: str = "0" * 64) -> RagEmbeddingModel:
    """Deterministic offline embedder with controlled directions.

    ``NEAR::`` texts share one direction (mutual cosine distance 0),
    ``FAR::`` texts sit orthogonally (distance 1.0 > max_distance=0.40);
    anything else maps to a stable angle derived from its bytes. No model
    download ever occurs: the frozen real model is validated only by the
    ``manage_rag.py add`` ticket command.
    """

    def _embed(texts: Any) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            if str(text).startswith("NEAR::"):
                raw = [1.0, 0.0]
            elif str(text).startswith("FAR::"):
                raw = [0.0, 1.0]
            else:
                digest = hashlib.sha256(str(text).encode("utf-8")).digest()
                raw = [digest[0] / 255.0, digest[1] / 255.0]
            norm = (raw[0] * raw[0] + raw[1] * raw[1]) ** 0.5 or 1.0
            vectors.append([value / norm for value in raw])
        return vectors

    return RagEmbeddingModel(
        model_id=EMBEDDING_MODEL_NAME, fingerprint=fingerprint, embed=_embed
    )


def _config(**overrides: Any) -> RagToolConfig:
    values: dict[str, Any] = {
        "enabled": True,
        "max_cases": 150,
        "k": 3,
        "max_distance": 0.40,
        "max_case_chars": 1200,
        "embedding_model": EMBEDDING_MODEL_NAME,
    }
    values.update(overrides)
    return RagToolConfig(**values)


def _adapter(
    tmp_path: Path,
    *,
    embedder: Any = None,
    protected: Any = (),
    **config_overrides: Any,
) -> RagAdapter:
    return RagAdapter(
        _config(**config_overrides),
        tmp_path / "chroma",
        embedder=embedder if embedder is not None else _stub_embedder(),
        protected_family_groups=protected,
    )


def _case(**overrides: Any) -> RagSourceCase:
    values: dict[str, Any] = {
        "case_id": "rag_case_00001",
        "public_source_url": "https://public.example.org/nazario-2025",
        "dataset": "nazario",
        "record_sha256": "a" * 64,
        "validated_label": "phishing",
        "analyst_validation_ref": "astra_gold_ai_v1",
        "duplicate_group": "dup:case00001",
        "family_group": "fam:case00001",
        "text_excerpt": "NEAR::Dear customer, verify your account within 24 hours",
        "analyst_rationale": "Public reference excerpt (test-only synthetic record).",
        "is_public": True,
        "split": "rag_reference",
    }
    for key, value in overrides.items():
        values[{"family": "family_group", "duplicate": "duplicate_group", "text": "text_excerpt", "campaign": "campaign_id"}.get(key, key)] = value
    return RagSourceCase.model_validate(values)


def _query() -> str:
    return "NEAR::Dear customer, verify your account within 24 hours"


# ---------------------------------------------------------------------------
# Source contract (no storage needed)
# ---------------------------------------------------------------------------


def test_source_case_accepts_public_validated_record() -> None:
    case = _case()
    assert case.is_public is True
    assert case.split == "rag_reference"
    assert case.campaign_id is None


def test_source_case_refuses_private_record() -> None:
    row = _case().model_dump(mode="json")
    row["is_public"] = False
    with pytest.raises(ValidationError):
        RagSourceCase.model_validate(row)


@pytest.mark.parametrize("split", ["dev", "test", "candidate", "excluded"])
def test_source_case_refuses_gold_and_non_rag_splits(split: str) -> None:
    row = _case().model_dump(mode="json")
    row["split"] = split
    with pytest.raises(ValidationError):
        RagSourceCase.model_validate(row)


def test_source_case_refuses_unvalidated_record() -> None:
    row = _case().model_dump(mode="json")
    row["analyst_validation_ref"] = ""
    with pytest.raises(ValidationError):
        RagSourceCase.model_validate(row)


def test_source_case_refuses_malformed_hash_and_url() -> None:
    with pytest.raises(ValidationError):
        _case(record_sha256=("ab" * 31) + "CD")
    with pytest.raises(ValidationError):
        _case(public_source_url="not-a-url")


def test_source_case_rejects_unknown_fields() -> None:
    row = _case().model_dump(mode="json")
    row["label_rationale"] = "an extra field is refused"
    with pytest.raises(ValidationError):
        RagSourceCase.model_validate(row)


# ---------------------------------------------------------------------------
# Indexing (temporary Chroma)
# ---------------------------------------------------------------------------


def test_add_counts_and_is_idempotent(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path)
    cases = [
        _case(case_id="rag_case_00001", family="fam:case00001"),
        _case(case_id="rag_case_00002", family="fam:case00002"),
    ]
    assert adapter.add(cases) == 2
    assert adapter.count() == 2
    assert adapter.add(cases) == 0  # identical re-add: no-op, no duplication
    assert adapter.count() == 2
    assert adapter.add([]) == 0
    assert adapter.count() == 2


def test_add_refuses_different_content_under_existing_id(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path)
    adapter.add([_case(case_id="rag_case_00001")])
    with pytest.raises(RagIndexError):
        adapter.add([_case(case_id="rag_case_00001", text="NEAR::Different public body text")])


def test_retrieved_case_keeps_the_source_rationale(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    """analyst_rationale is persisted and returned by search, not dropped."""

    adapter = _adapter(tmp_path)
    source = _case(
        analyst_rationale="AI-adjudicated reference rationale: credential-verify flow."
    )
    adapter.add([source])
    hits = adapter.search(_query(), k=1)
    assert len(hits) == 1
    assert hits[0].analyst_rationale == source.analyst_rationale
    assert hits[0].analyst_validation_ref == source.analyst_validation_ref


def test_add_refuses_a_changed_rationale_under_the_same_case_id(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    """A changed rationale under an existing case_id is a divergent replay."""

    adapter = _adapter(tmp_path)
    adapter.add([_case(analyst_rationale="Original AI-adjudicated rationale.")])
    # Same text excerpt, same id, same label: ONLY the rationale changed.
    with pytest.raises(RagIndexError):
        adapter.add([_case(analyst_rationale="Rewritten rationale after adjudication.")])


def test_add_refuses_second_case_of_an_indexed_family(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path)
    adapter.add([_case(case_id="rag_case_00001", family="fam:case00001")])
    with pytest.raises(RagIndexError):
        adapter.add([_case(case_id="rag_case_00002", family="fam:case00001")])


def test_add_refuses_twice_the_same_family_in_one_batch(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path)
    with pytest.raises(RagSourceError):
        adapter.add(
            [
                _case(case_id="rag_case_00001", family="fam:case00001"),
                _case(case_id="rag_case_00002", family="fam:case00001"),
            ]
        )


def test_add_refuses_protected_gold_family(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path, protected={"fam:gold_dev_00001"})
    with pytest.raises(RagSourceError):
        adapter.add([_case(case_id="rag_case_00001", family="fam:gold_dev_00001")])


def test_add_refuses_oversized_excerpt(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path, max_case_chars=64)
    with pytest.raises(RagSourceError):
        adapter.add([_case(case_id="rag_case_00001", text="NEAR::" + "x" * 64)])


def test_add_enforces_max_cases(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path, max_cases=1)
    adapter.add([_case(case_id="rag_case_00001")])
    with pytest.raises(RagIndexError):
        adapter.add([_case(case_id="rag_case_00002", family="fam:case00002")])


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


def test_search_returns_the_identical_public_case(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path)
    case = _case(case_id="rag_case_00001", family="fam:case00001")
    adapter.add([case])
    hits = adapter.search(_query())
    assert len(hits) == 1
    hit = hits[0]
    assert hit.case_id == case.case_id
    assert hit.family_group == case.family_group
    assert hit.duplicate_group == case.duplicate_group
    assert hit.validated_label == "phishing"
    assert hit.public_source_url == case.public_source_url
    assert hit.analyst_validation_ref == "astra_gold_ai_v1"
    assert hit.is_public is True
    assert hit.split == "rag_reference"
    assert hit.distance <= 0.40
    assert hit.embedding_model_id == adapter.embedding_model_id()
    assert hit.text_excerpt == case.text_excerpt


def test_search_excludes_the_current_message_family(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path)
    adapter.add([_case(case_id="rag_case_00001", family="fam:case00001")])
    assert adapter.search(_query(), exclusions={"fam:case00001"}) == []
    assert adapter.search(_query(), exclusions={"dup:case00001"}) == []
    assert len(adapter.search(_query(), exclusions={"fam:unrelated"})) == 1


def test_search_excludes_by_campaign(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path)
    adapter.add(
        [_case(case_id="rag_case_00001", family="fam:case00001", campaign="camp:2025-04")]
    )
    assert adapter.search(_query(), exclusions={"camp:2025-04"}) == []
    assert len(adapter.search(_query(), exclusions={"camp:2025-05"})) == 1


def test_search_respects_distance_threshold_and_never_forces(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path, embedder=_stub_embedder())
    adapter.add(
        [_case(case_id="rag_case_00001", family="fam:case00001", text="FAR::unrelated public text")]
    )
    assert adapter.search(_query()) == []  # no forced neighbour beyond the threshold
    assert len(adapter.search("FAR::unrelated public text")) == 1  # distance 0 within threshold


def test_search_k_is_deterministic_and_bounded(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    adapter = _adapter(tmp_path, embedder=_stub_embedder())
    adapter.add(
        [
            _case(case_id="rag_case_00001", family="fam:case00001", text="NEAR::unpaid invoice payment"),
            _case(case_id="rag_case_00002", family="fam:case00002", text="NEAR::unpaid invoice payment"),
            _case(case_id="rag_case_00003", family="fam:case00003", text="NEAR::unpaid invoice payment"),
        ]
    )
    assert adapter.search("NEAR::unpaid invoice payment", k=0) == []
    two = adapter.search("NEAR::unpaid invoice payment", k=2)
    assert [case.case_id for case in two] == ["rag_case_00001", "rag_case_00002"]
    all_hits = adapter.search("NEAR::unpaid invoice payment", k=99)
    assert [case.case_id for case in all_hits] == [
        "rag_case_00001",
        "rag_case_00002",
        "rag_case_00003",
    ]
    again = adapter.search("NEAR::unpaid invoice payment", k=99)
    assert [case.case_id for case in again] == [case.case_id for case in all_hits]
    with pytest.raises(ValueError):
        adapter.search("NEAR::unpaid invoice payment", k=-1)


def test_search_returns_one_case_per_family(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path, embedder=_stub_embedder())
    adapter.add(
        [
            _case(case_id="rag_case_00001", family="fam:case00001", text="NEAR::shipping invoice attached"),
            _case(case_id="rag_case_00002", family="fam:case00002", text="NEAR::shipping invoice attached"),
        ]
    )
    hits = adapter.search("NEAR::shipping invoice attached", k=3)
    assert {case.family_group for case in hits} == {"fam:case00001", "fam:case00002"}
    assert len(hits) == 2


# ---------------------------------------------------------------------------
# Persistence, clear, frozen fingerprint, missing dependency
# ---------------------------------------------------------------------------


def test_index_persists_across_adapter_instances(tmp_path: Path, chromadb_or_skip: None) -> None:
    embedder = _stub_embedder()
    index_dir = tmp_path / "chroma"
    RagAdapter(_config(), index_dir, embedder=embedder).add(
        [_case(case_id="rag_case_00001", family="fam:case00001")]
    )
    second = RagAdapter(_config(), index_dir, embedder=embedder)
    assert second.count() == 1
    hits = second.search(_query())
    assert [case.case_id for case in hits] == ["rag_case_00001"]


def test_clear_empties_the_index(tmp_path: Path, chromadb_or_skip: None) -> None:
    adapter = _adapter(tmp_path)
    adapter.add([_case(case_id="rag_case_00001", family="fam:case00001")])
    adapter.clear()
    assert adapter.count() == 0
    assert adapter.search(_query()) == []
    adapter.add([_case(case_id="rag_case_00002", family="fam:case00002")])
    assert adapter.count() == 1


def test_embedding_fingerprint_is_frozen_in_the_collection_metadata(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    index_dir = tmp_path / "chroma"
    RagAdapter(_config(), index_dir, embedder=_stub_embedder("0" * 64)).add(
        [_case(case_id="rag_case_00001", family="fam:case00001")]
    )
    with pytest.raises(RagModelError):
        RagAdapter(_config(), index_dir, embedder=_stub_embedder("f" * 64)).count()


def test_missing_chromadb_dependency_is_a_typed_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REAL missing-dependency simulation: `import chromadb` raises.

    ``sys.modules['chromadb'] = None`` makes the real import raise
    ImportError, which the lazy gate converts into the typed refusal.
    """

    monkeypatch.setitem(sys.modules, "chromadb", None)
    adapter = RagAdapter(_config(), tmp_path / "chroma", embedder=_stub_embedder())
    with pytest.raises(RagUnavailableError):
        adapter.add([_case(case_id="rag_case_00001", family="fam:case00001")])


def test_rejects_a_non_frozen_embedding_model_name(tmp_path: Path) -> None:
    with pytest.raises(RagModelError):
        RagAdapter(
            _config(embedding_model="other-model"),
            tmp_path / "chroma",
            embedder=_stub_embedder(),
        )


def test_default_embedder_is_frozen_when_weights_are_cached() -> None:
    """REAL embedding path: only validated when the operator cached it offline.

    The frozen chromadb ONNX archive is never downloaded by tests; on a
    machine without the cache the real path is validated by
    ``python scripts/manage_rag.py add`` instead.
    """

    weights = Path.home() / ".cache" / "chroma" / "onnx_models" / "all-MiniLM-L6-v2" / "onnx" / "model.onnx"
    if not weights.is_file():
        pytest.skip("frozen ONNX model not cached; validated by scripts/manage_rag.py add")
    from src.tools.rag import default_embedder

    embedder = default_embedder()
    assert embedder.model_id == "all-MiniLM-L6-v2"
    assert len(embedder.fingerprint) == 64 and embedder.fingerprint == embedder.fingerprint.lower()
    vector = embedder.embed(["verify your account"])[0]
    again = embedder.embed(["verify your account"])[0]
    assert vector == again  # deterministic embeddings
    assert all(value == value for value in vector)


# ---------------------------------------------------------------------------
# Deterministic query projection
# ---------------------------------------------------------------------------


def _parsed(
    subject: str | None = "Verify your account",
    *,
    text: str = "",
    html: str | None = None,
) -> ParsedEmail:
    parts: list[TextPart] = []
    if text:
        parts.append(TextPart(part_id="part_1", mime_type="text/plain", text=text))
    if html is not None:
        parts.append(TextPart(part_id="part_2", mime_type="text/html", text=html))
    return ParsedEmail(
        email_sha256="a" * 64,
        raw_size_bytes=2048,
        input_format="rfc822",
        subject=subject,
        text_parts=parts,
    )


def test_rag_query_from_parsed_prefers_subject_and_text_parts() -> None:
    query = rag_query_from_parsed(_parsed(text="Your mailbox will be suspended today."), 1200)
    assert query == "Verify your account\nYour mailbox will be suspended today."


def test_rag_query_from_parsed_falls_back_to_html_parts() -> None:
    query = rag_query_from_parsed(_parsed(text="", html="<p>HTML only body</p>"), 1200)
    assert "HTML only body" in query


def test_rag_query_from_parsed_truncates_deterministically() -> None:
    query = rag_query_from_parsed(_parsed(text="x" * 500), 32)
    assert len(query) == 32
    assert query == rag_query_from_parsed(_parsed(text="x" * 500), 32)


def test_rag_query_from_parsed_handles_empty_inputs() -> None:
    assert rag_query_from_parsed(None, 1200) == ""
    assert rag_query_from_parsed(_parsed(subject=None, text=""), 1200) == ""
    assert rag_query_from_parsed(_parsed(), 0) == ""


# ---------------------------------------------------------------------------
# Disabled mode (subprocess import isolation)
# ---------------------------------------------------------------------------


def _run_python(code: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT,
        shell=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


def test_rag_module_import_loads_neither_chromadb_nor_weights() -> None:
    probe = (
        "import sys\n"
        "import src.tools.rag\n"
        "import src.graph\n"
        "print('chromadb' in sys.modules, 'onnxruntime' in sys.modules, 'tokenizers' in sys.modules)\n"
    )
    result = _run_python(probe)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "False False False", result.stdout


def test_adapter_construction_stays_lazy_until_first_use(tmp_path: Path) -> None:
    probe = (
        "import sys\n"
        "from pathlib import Path\n"
        "from src.config import RagToolConfig\n"
        "from src.tools.rag import RagAdapter, deterministic_stub_embedder\n"
        "adapter = RagAdapter(\n"
        "    RagToolConfig(enabled=True, max_cases=2, k=1, max_distance=0.4, "
        "max_case_chars=64, embedding_model='all-MiniLM-L6-v2'),\n"
        f"    Path(r'{tmp_path / 'chroma'}'),\n"
        "    embedder=deterministic_stub_embedder(),\n"
        ")\n"
        "print('chromadb' in sys.modules, 'onnxruntime' in sys.modules, adapter is not None)\n"
    )
    result = _run_python(probe)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "False False True", result.stdout


def test_disabled_factory_imports_nothing_and_returns_none() -> None:
    probe = (
        "import sys\n"
        "from src.config import RagToolConfig, load_settings\n"
        "from src.tools.rag import create_rag_adapter_if_enabled\n"
        "config = RagToolConfig(enabled=True, max_cases=2, k=1, max_distance=0.4, "
        "max_case_chars=64, embedding_model='all-MiniLM-L6-v2')\n"
        "assert create_rag_adapter_if_enabled(load_settings(None), config) is None\n"
        "print('chromadb' in sys.modules, 'onnxruntime' in sys.modules, 'tokenizers' in sys.modules)\n"
    )
    result = _run_python(probe)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "False False False", result.stdout


# ---------------------------------------------------------------------------
# Services factory wiring
# ---------------------------------------------------------------------------


def test_build_services_default_settings_disable_the_rag(tmp_path: Path) -> None:
    settings = load_settings(None).model_copy(update={"RUNS_DIR": tmp_path / "runs"})
    services = build_services(
        settings,
        source_profile="fixture",  # type: ignore[arg-type]
        run_id=str(uuid.uuid4()),
        started_monotonic=time.monotonic(),
    )
    assert services.rag is None
    assert services.rag_exclusions == set()
    assert services.current_family_group is None
    assert services.current_duplicate_group is None
    assert services.current_campaign_id is None


def test_build_services_rag_enabled_builds_a_lazy_adapter(
    tmp_path: Path, project_root: Path
) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    tools_source = (project_root / "configs" / "tools.yaml").read_text(encoding="utf-8")
    marker = (
        "rag:\n"
        "  # Globally piloted by RAG_ENABLED (default false); inactive before G7-A.\n"
        "  enabled: false\n"
    )
    if marker not in tools_source:
        pytest.fail("configs/tools.yaml rag section changed: update this fixture")
    (config_dir / "tools.yaml").write_text(
        tools_source.replace(marker, "rag:\n  enabled: true\n"), encoding="utf-8"
    )
    for name in ("gate.yaml", "policy.yaml"):
        (config_dir / name).write_bytes((project_root / "configs" / name).read_bytes())

    settings = load_settings(None).model_copy(
        update={
            "RUNS_DIR": tmp_path / "runs",
            "CONFIG_DIR": config_dir,
            "RAG_DIR": tmp_path / "chroma",
            "RAG_ENABLED": True,
        }
    )
    services = build_services(
        settings,
        source_profile="fixture",  # type: ignore[arg-type]
        run_id=str(uuid.uuid4()),
        started_monotonic=time.monotonic(),
        rag_exclusions={"fam:gold_current"},
        current_family_group="fam:gold_current",
    )
    assert services.rag is not None
    assert services.rag_exclusions == {"fam:gold_current"}
    assert services.current_family_group == "fam:gold_current"
    assert Path(str(settings.RAG_DIR)) == tmp_path / "chroma"


def test_build_services_accepts_effective_tools_and_adapter_override(
    tmp_path: Path, project_root: Path
) -> None:
    """Paired-ablation seam: effective in-memory tools + ONE injected adapter.

    The evaluator (docs/evaluation.md §8.7) runs the ablation under an
    effective configuration (RAG enabled in memory, the frozen tools.yaml
    file unchanged) and reuses the SAME validated adapter for every sample.
    """

    settings = load_settings(None).model_copy(
        update={
            "RUNS_DIR": tmp_path / "runs",
            "CONFIG_DIR": project_root / "configs",
            "RAG_DIR": tmp_path / "chroma",
            "RAG_ENABLED": True,
        }
    )
    tools = load_yaml_config(project_root / "configs" / "tools.yaml", ToolsConfig)
    assert tools.rag.enabled is False  # the frozen file is unchanged
    effective = tools.model_copy(
        update={"rag": tools.rag.model_copy(update={"enabled": True})}
    )
    adapter = _adapter(tmp_path)  # stub embedder: no real weights loaded
    services = build_services(
        settings,
        source_profile="fixture",  # type: ignore[arg-type]
        run_id=str(uuid.uuid4()),
        started_monotonic=time.monotonic(),
        tools_override=effective,
        rag=adapter,
    )
    assert services.rag is adapter
    assert services.tools_config.rag.enabled is True
    assert Path(str(settings.RAG_DIR)) == tmp_path / "chroma"


# ---------------------------------------------------------------------------
# REAL repo data: public-only + gold isolation of public_cases.jsonl
# ---------------------------------------------------------------------------


def test_real_public_cases_are_public_validated_and_dev_gold_isolated() -> None:
    """Real corpus: public artifact valid, DEV isolation, test sealed.

    ``gold_test.jsonl`` is NEVER opened before T19E (build agents have no
    access to the sealed partition): the RAG/test disjointness is inherited
    from the TICKET-13 deterministic split construction and only the seal
    aggregate is checked here.
    """

    import scripts.manage_rag as manage_rag

    cases = manage_rag.load_public_cases(PROJECT_ROOT / "corpus" / "rag" / "public_cases.jsonl")
    assert len(cases) == 150
    assert len({case.family_group for case in cases}) == 150
    assert all(case.is_public is True for case in cases)
    assert all(case.split == "rag_reference" for case in cases)
    assert {case.analyst_validation_ref for case in cases} == {"astra_gold_ai_v1"}

    guard = manage_rag.gold_isolation_guard(
        PROJECT_ROOT / "corpus" / "gold" / "gold_dev.jsonl",
        PROJECT_ROOT / "corpus" / "gold" / "test_seal.json",
    )
    rag_families = {case.family_group for case in cases}
    rag_hashes = {case.record_sha256 for case in cases}
    assert not (rag_families & guard.families)
    assert not (rag_hashes & guard.record_sha256)
    assert guard.summary["gold_test_opened"] is False
    assert guard.summary["protected_family_count"] == 83
    assert guard.summary["protected_record_hash_count"] == 83
    seal = guard.summary["gold_test_seal"]
    assert seal["record_count"] == seal["family_count"] == 83
    assert seal["human_validated"] is False
    assert seal["reviewer_ref"] == "astra_gold_ai_v1"
    assert seal["rag_families_reserved_before_dev_test_split"] is True


def test_manage_rag_never_opens_gold_test(
    monkeypatch: pytest.MonkeyPatch, project_root: Path
) -> None:
    """Track every file the T15 guard reads; gold_test never appears.

    Path.open / read_bytes / read_text are wrapped (still calling the
    originals) so any attempted access to gold_test.jsonl would be recorded.
    """

    import scripts.manage_rag as manage_rag

    touched: list[str] = []

    original_open = Path.open
    original_read_bytes = Path.read_bytes
    original_read_text = Path.read_text

    def _record(original, self_path: Path, *args: object, **kwargs: object):
        touched.append(str(self_path))
        return original(self_path, *args, **kwargs)

    monkeypatch.setattr(
        Path, "open", lambda self, *a, **k: _record(original_open, self, *a, **k)
    )
    monkeypatch.setattr(
        Path, "read_bytes", lambda self, *a, **k: _record(original_read_bytes, self, *a, **k)
    )
    monkeypatch.setattr(
        Path, "read_text", lambda self, *a, **k: _record(original_read_text, self, *a, **k)
    )

    cases = manage_rag.load_public_cases(
        project_root / "corpus" / "rag" / "public_cases.jsonl"
    )
    guard = manage_rag.gold_isolation_guard(
        project_root / "corpus" / "gold" / "gold_dev.jsonl",
        project_root / "corpus" / "gold" / "test_seal.json",
    )
    assert cases and guard.families
    assert any(str(path).endswith("gold_dev.jsonl") for path in touched)
    assert any(str(path).endswith("test_seal.json") for path in touched)
    assert not any("gold_test" in str(path) for path in touched)


# ---------------------------------------------------------------------------
# Graph node wiring
# ---------------------------------------------------------------------------


class RecordingRagAdapter:
    """Controlled adapter: records search calls, returns fixed cases/errors."""

    def __init__(self, cases: list[RagCase] | None = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._cases = cases if cases is not None else []
        self._error = error

    def search(self, query: str, exclusions: Any = None, k: int = 3) -> list[RagCase]:
        self.calls.append({"query": query, "exclusions": set(exclusions or ()), "k": k})
        if self._error is not None:
            raise self._error
        return list(self._cases)


class FakeToolAdapter:
    """Controlled tool adapter: records calls, returns a typed skipped."""

    def __init__(self, tool: str) -> None:
        self.tool = tool
        self.calls: list[str] = []

    def lookup(self, query: Observable, context: Any) -> ToolResult:
        self.calls.append(query.id)
        return ToolResult(
            tool=self.tool,  # type: ignore[arg-type]
            query_observable_id=query.id,
            status="skipped",
            reason="disabled",
            mode="none",
        )

    def scan(self, query: Observable, context: Any) -> ToolResult:
        return self.lookup(query, context)


def _configs() -> tuple[ToolsConfig, GateConfig, PolicyConfig]:
    tools = load_yaml_config(PROJECT_ROOT / "configs" / "tools.yaml", ToolsConfig)
    gate = load_yaml_config(PROJECT_ROOT / "configs" / "gate.yaml", GateConfig)
    policy = load_yaml_config(PROJECT_ROOT / "configs" / "policy.yaml", PolicyConfig)
    assert isinstance(tools, ToolsConfig)
    assert isinstance(gate, GateConfig)
    assert isinstance(policy, PolicyConfig)
    return tools, gate, policy


def _rag_case() -> RagCase:
    return RagCase(
        case_id="rag_case_00001",
        public_source_url="https://public.example.org/nazario-2025",
        dataset="nazario",
        record_sha256="a" * 64,
        validated_label="phishing",
        analyst_validation_ref="astra_gold_ai_v1",
        campaign_id=None,
        duplicate_group="dup:case00001",
        family_group="fam:case00001",
        text_excerpt="NEAR::Dear customer, verify your account within 24 hours",
        analyst_rationale="Public reference excerpt (test-only synthetic record).",
        distance=0.0,
        embedding_model_id="all-MiniLM-L6-v2@sha256:" + "0" * 16,
        is_public=True,
        split="rag_reference",
    )


def _node_state(tmp_path: Path, *, with_parsed: bool = True) -> EmailTriageState:
    state = new_state((tmp_path / "email.eml").resolve(), "fixture", "a" * 64)
    if with_parsed:
        state.parsed = _parsed(text="Dear customer, verify your account within 24 hours.")
    return state


def _node_services(
    tmp_path: Path,
    *,
    rag: Any = None,
    exclusions: Any = None,
    current_family: str | None = None,
    current_duplicate: str | None = None,
    current_campaign: str | None = None,
) -> Services:
    settings = load_settings(None).model_copy(update={"RUNS_DIR": tmp_path / "runs"})
    tools, gate, policy = _configs()
    run_id = str(uuid.uuid4())
    run_dir = Path(settings.RUNS_DIR) / run_id
    return Services(
        settings=settings,
        tools_config=tools,
        gate_config=gate,
        policy_config=policy,
        vt=FakeToolAdapter("virustotal"),
        cti=FakeToolAdapter("opencti"),
        urlscan=FakeToolAdapter("urlscan"),
        luna=None,
        luna_final=None,
        egress=EgressConfig(allow_real_urls=False),
        run_dir=run_dir,
        capture_dir=run_dir / "responses",
        deadline=time.monotonic() + 60.0,
        clock=time.monotonic,
        started_monotonic=time.monotonic(),
        mode="recorded",
        rag=rag,
        rag_exclusions=set(exclusions or ()),
        current_duplicate_group=current_duplicate,
        current_family_group=current_family,
        current_campaign_id=current_campaign,
    )


def test_node_rag_lookup_passes_query_exclusions_and_k(tmp_path: Path) -> None:
    adapter = RecordingRagAdapter(cases=[_rag_case()])
    services = _node_services(tmp_path, rag=adapter, exclusions={"fam:gold_current"})
    patch = node_rag_lookup(_node_state(tmp_path), services)
    assert patch["enrichment"].rag == [_rag_case()]
    assert len(adapter.calls) == 1
    call = adapter.calls[0]
    assert "Dear customer, verify your account within 24 hours." in call["query"]
    assert call["exclusions"] == {"fam:gold_current"}
    assert call["k"] == services.tools_config.rag.k == 3
    assert patch["timings"].rag_ms >= 0.0


def test_node_rag_lookup_typed_failures_keep_context_empty(tmp_path: Path) -> None:
    unavailable = RecordingRagAdapter(error=RagUnavailableError("chromadb missing"))
    patch = node_rag_lookup(_node_state(tmp_path), _node_services(tmp_path, rag=unavailable))
    assert patch["enrichment"].rag == []
    assert [issue.code for issue in patch["errors"]] == ["rag_unavailable"]

    failed = RecordingRagAdapter(error=RagIndexError("family conflict"))
    patch_failed = node_rag_lookup(
        _node_state(tmp_path), _node_services(tmp_path, rag=failed)
    )
    assert patch_failed["enrichment"].rag == []
    assert [issue.code for issue in patch_failed["errors"]] == ["rag_lookup_failed"]

    unexpected = RecordingRagAdapter(error=RuntimeError("disk full"))
    patch_unexpected = node_rag_lookup(
        _node_state(tmp_path), _node_services(tmp_path, rag=unexpected)
    )
    assert patch_unexpected["enrichment"].rag == []
    assert [issue.code for issue in patch_unexpected["errors"]] == ["rag_lookup_failed"]


def test_node_rag_lookup_no_call_without_adapter_or_query(tmp_path: Path) -> None:
    adapter = RecordingRagAdapter(cases=[_rag_case()])
    services = _node_services(tmp_path, rag=adapter)
    patch = node_rag_lookup(_node_state(tmp_path, with_parsed=False), services)
    assert patch["enrichment"].rag == []
    assert patch["errors"] == []
    assert adapter.calls == []  # parse failure: no RAG call, no fabricated context

    empty_state = _node_state(tmp_path)
    empty_state.parsed = _parsed(subject=None, text="")
    patch_empty = node_rag_lookup(empty_state, services)
    assert patch_empty["enrichment"].rag == []
    assert adapter.calls == []  # empty query: no call

    disabled = _node_services(tmp_path, rag=None)
    patch_disabled = node_rag_lookup(_node_state(tmp_path), disabled)
    assert patch_disabled["enrichment"].rag == []
    assert patch_disabled["errors"] == []


def test_node_verify_carries_current_groups_into_run_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import src.graph as graph_module
    from src.verify import RunContext

    captured: dict[str, Any] = {}

    class Recorder(RunContext):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            captured.update(kwargs)

    monkeypatch.setattr(graph_module, "RunContext", Recorder)
    services = _node_services(
        tmp_path,
        current_family="fam:gold_current",
        current_duplicate="dup:gold_current",
        current_campaign="camp:2025",
    )
    state = _node_state(tmp_path, with_parsed=False)
    graph_module.node_verify(state, services)
    assert captured["current_family_group"] == "fam:gold_current"
    assert captured["current_duplicate_group"] == "dup:gold_current"
    assert captured["current_campaign_id"] == "camp:2025"


# ---------------------------------------------------------------------------
# FULL controlled graph run over a REAL temporary public index
# ---------------------------------------------------------------------------


def _fake_luna(phase: str, label: str, confidence: float) -> Any:
    """Controlled LLM client: valid Assessment payloads, no network."""

    labels = ["spear_phishing", "phishing", "fraude", "menace", "spam", "legitime"]
    remaining = [name for name in labels if name != label]
    share = round((1.0 - confidence) / len(remaining), 9)
    values = {name: share for name in remaining}
    values[label] = confidence
    drift = round(1.0 - sum(values.values()), 9)
    values[remaining[0]] = round(values[remaining[0]] + drift, 9)
    payload = {
        "probabilities": values,
        "observations": [],
        "inferences": [],
        "observable_assessments": [],
        "needs_enrichment": False,
        "missing_information": [],
        "decisive_evidence_ids": [],
    }

    class _FakeLuna:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        def complete_json(
            self,
            messages: list[dict[str, Any]],
            schema: dict[str, Any],
            effort: str,
            max_output_tokens: int,
            deadline: float,
        ) -> tuple[dict[str, Any], CallRecord]:
            self.calls.append({"effort": effort, "messages": messages})
            return dict(payload), CallRecord(
                phase=phase,  # type: ignore[arg-type]
                status="ok",
                attempts=1,
                requested_model="fake",
                returned_model="fake",
                reasoning_effort=effort,  # type: ignore[arg-type]
            )

    return _FakeLuna()


def _write_eml(tmp_path: Path, body: str) -> Path:
    raw = (
        "From: a@example.org\n"
        "To: b@example.org\n"
        "Subject: NEAR::Verify your account\n"
        "Date: Fri, 19 Sep 2026 10:00:00 +0000\n"
        "Message-ID: <rag-graph-test@example.org>\n"
        "MIME-Version: 1.0\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        f"{body}\n"
    )
    path = tmp_path / "email.eml"
    path.write_bytes(raw.encode("utf-8"))
    return path


def test_full_graph_feeds_public_neighbour_and_excludes_current_family(
    tmp_path: Path, chromadb_or_skip: None
) -> None:
    """A controlled COMPLEX run with a REAL adapter over a temporary index.

    The indexed public neighbour is retrieved (one case, distance 0) and
    the FINAL audit records ``rag_case_count_sent == 1``; the same index
    with the current email's own family in the exclusions returns NOTHING
    and no contamination issue. Fake Luna/tools only: never a provider
    observation, never a simulated RAG answer — the neighbour text is the
    one really indexed.
    """

    body = "Verify now: https://phishing.test/verify?token=abc and confirm."
    email = _write_eml(tmp_path, body)
    index_dir = tmp_path / "chroma"
    adapter = RagAdapter(_config(), index_dir, embedder=_stub_embedder())
    adapter.add([_case(case_id="rag_case_00001", family="fam:case00001")])

    def _services_with(exclusions: set[str], luna: Any, luna_final: Any) -> Services:
        settings = load_settings(None).model_copy(
            update={
                "RUNS_DIR": tmp_path / "runs",
                "RAG_DIR": index_dir,
                "LITELLM_API_KEY": SecretStr("placeholder-key-not-a-real-credential"),
            }
        )
        tools, gate, policy = _configs()
        run_id = str(uuid.uuid4())
        run_dir = Path(settings.RUNS_DIR) / run_id
        return Services(
            settings=settings,
            tools_config=tools,
            gate_config=gate,
            policy_config=policy,
            vt=FakeToolAdapter("virustotal"),
            cti=FakeToolAdapter("opencti"),
            urlscan=FakeToolAdapter("urlscan"),
            luna=luna,
            luna_final=luna_final,
            egress=EgressConfig(allow_real_urls=False),
            run_dir=run_dir,
            capture_dir=run_dir / "responses",
            deadline=time.monotonic() + 60.0,
            clock=time.monotonic,
            started_monotonic=time.monotonic(),
            mode="recorded",
            rag=adapter,
            rag_exclusions=exclusions,
            current_family_group="fam:gold_current",
        )

    def _final_rag_context(luna_final: Any) -> list[Any]:
        """RAG_CONTEXT really handed to the FINAL transport for that call."""

        assert luna_final.calls, "the FINAL phase must really call the client"
        envelope = json.loads(luna_final.calls[-1]["messages"][-1]["content"])
        return envelope["RAG_CONTEXT"]

    luna = _fake_luna("internal", "phishing", 0.90)
    luna_final = _fake_luna("final", "phishing", 0.92)
    state = new_state(email.resolve(), "fixture", "a" * 64)
    final_state = build_graph(_services_with(set(), luna, luna_final)).invoke(
        state, config={"configurable": {"thread_id": state.run_id}}
    )
    assert final_state["gate"].decision == "complex"
    assert len(final_state["enrichment"].rag) == 1
    hit = final_state["enrichment"].rag[0]
    assert hit.case_id == "rag_case_00001"
    assert hit.family_group == "fam:case00001"
    assert hit.distance <= 0.40

    run_dir = Path(final_state["report_path"]).parent
    events = [
        json.loads(line)
        for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    rag_event = [event for event in events if event.get("node") == "rag_lookup"]
    assert rag_event and rag_event[0]["cases"] == 1

    rag_context = _final_rag_context(luna_final)
    assert len(rag_context) == 1
    assert rag_context[0]["case_id"] == "rag_case_00001"
    assert rag_context[0]["validated_label"] == "phishing"
    assert "rag_contamination" not in [issue.code for issue in final_state["verification"]]

    excluded_state = new_state(email.resolve(), "fixture", "a" * 64)
    excluded_final_call = _fake_luna("final", "phishing", 0.92)
    excluded_final = build_graph(
        _services_with(
            {"fam:case00001", "dup:case00001"},
            _fake_luna("internal", "phishing", 0.90),
            excluded_final_call,
        )
    ).invoke(excluded_state, config={"configurable": {"thread_id": excluded_state.run_id}})
    assert excluded_final["enrichment"].rag == []
    assert _final_rag_context(excluded_final_call) == []
    assert "rag_contamination" not in [issue.code for issue in excluded_final["verification"]]

