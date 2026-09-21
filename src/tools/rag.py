"""Local public-only RAG adapter (TICKET-15, gate G7-A).

Implements the frozen contract of docs/tickets/TICKET-15.md and
docs/corpus.md §7.6 inside docs/contracts.md §2.4/§2.7/§2.8:

- ``add(cases) -> int`` / ``search(query, exclusions, k=3) -> list[RagCase]``
  / ``clear() -> None`` on ONE local embedded Chroma collection
  (``public_rag_reference``, cosine space) stored under ``RAG_DIR``
  (default ``corpus/rag/chroma``, git-ignored). No remote vector service,
  no second vector database, no GraphRAG, no query-rewriting LLM.
- Every indexed case must be ``is_public=True`` and ``split=rag_reference``
  (validated label + validation reference mandatory). Private, gold
  (``split=dev|test``) or unconfirmed cases are refused at index time;
  Gold family groups and Gold record hashes are refused when the guard is
  provided by the caller (``protected_family_groups``).
- Retrieval asks Chroma for ALL candidates (the index is bounded by
  ``max_cases``) and filters LOCALLY: distance ≤ ``max_distance`` (0.40),
  the caller's exclusions matched against ``family_group`` /
  ``duplicate_group`` / ``campaign_id``, at most one neighbour per
  ``family_group``, deterministic ``(distance, case_id)`` order, exactly
  ``k`` results maximum — never a forced neighbour (docs/corpus.md §7.6).
- Embedding: chromadb's ONNX ``all-MiniLM-L6-v2``; the model id and the
  SHA-256 fingerprint of the frozen ONNX weights are stored in the
  collection metadata and verified on EVERY open — a changed embedding
  space is refused instead of silently mixing vectors. Only
  ``text_excerpt`` is embedded: labels, rationale and ids never enter the
  embedding text (docs/corpus.md §7.6).
- Disabled mode (``RAG_ENABLED=false``, the frozen G6 baseline): the
  factory returns ``None`` and NEITHER Chroma nor the ONNX weights are
  imported. Even a constructed adapter imports its storage stack lazily on
  the first ``add``/``search``/``clear``/``count`` call only.
- RAG neighbours are contextual analogies (INFERENCE, docs/contracts.md
  §2.4): they never join the observable registry of the current message
  and never carry a fifth provenance.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, field_validator

from ..config import Label, RagToolConfig, Settings
from ..state import RagCase

#: Frozen collection name: one public collection, nothing else is created.
COLLECTION_NAME = "public_rag_reference"

#: Frozen embedding identifier prefix; the full id carries the fingerprint.
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

#: Local chromadb directory layout of the frozen ONNX MiniLM model.
_ONNX_MODEL_RELATIVE = Path("onnx") / "model.onnx"


class RagError(RuntimeError):
    """Typed RAG failure; never silently degraded, never fabricated."""


class RagUnavailableError(RagError):
    """A required optional dependency (chromadb/onnxruntime) is missing."""


class RagSourceError(RagError):
    """A case violates the public/validated source contract — refused."""


class RagIndexError(RagError):
    """The index would become inconsistent (duplicate id, family conflict)."""


class RagModelError(RagError):
    """The embedding model no longer matches the frozen index fingerprint."""


class RagSourceCase(BaseModel):
    """Source record of ``corpus/rag/public_cases.jsonl`` (contracts §2.8).

    Closed schema, ``extra='forbid'``: exactly the artifact fields, WITHOUT
    ``distance`` and ``embedding_model_id`` (both are produced by search,
    never by the source). ``is_public`` and ``split`` are frozen Literals:
    a private, gold or differently-split record cannot even be constructed.
    """

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    case_id: str
    public_source_url: str
    dataset: str
    record_sha256: str
    validated_label: Label
    analyst_validation_ref: str
    campaign_id: str | None = None
    duplicate_group: str
    family_group: str
    text_excerpt: str
    analyst_rationale: str
    is_public: Literal[True] = True
    split: Literal["rag_reference"] = "rag_reference"

    @field_validator("case_id", "dataset", "duplicate_group", "family_group")
    @classmethod
    def _non_empty_identifier(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identifier fields must be non-empty")
        return value

    @field_validator("record_sha256")
    @classmethod
    def _sha256_format(cls, value: str) -> str:
        if len(value) != 64 or value != value.lower() or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("record_sha256 must be 64 lowercase hex characters")
        return value

    @field_validator("analyst_validation_ref")
    @classmethod
    def _validated_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("analyst_validation_ref is mandatory (validated case)")
        return value

    @field_validator("public_source_url")
    @classmethod
    def _public_url(cls, value: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("public_source_url must be an HTTP(S) URL")
        return value

    def public_payload(self) -> dict[str, Any]:
        """Chroma-compatible metadata without null values (Chroma refuses None)."""

        payload: dict[str, Any] = {
            "case_id": self.case_id,
            "public_source_url": self.public_source_url,
            "dataset": self.dataset,
            "record_sha256": self.record_sha256,
            "validated_label": self.validated_label,
            "analyst_validation_ref": self.analyst_validation_ref,
            "duplicate_group": self.duplicate_group,
            "family_group": self.family_group,
            "is_public": True,
            "split": self.split,
        }
        if self.campaign_id is not None:
            payload["campaign_id"] = self.campaign_id
        return payload


@dataclass(frozen=True)
class RagEmbeddingModel:
    """Frozen embedding function: id + SHA-256 fingerprint + embed callable."""

    model_id: str
    fingerprint: str
    embed: Callable[[Sequence[str]], list[list[float]]]

    @property
    def qualified_id(self) -> str:
        """Id recorded on every produced ``RagCase`` (version + fingerprint)."""

        return f"{self.model_id}@sha256:{self.fingerprint[:16]}"


def deterministic_stub_embedder() -> RagEmbeddingModel:
    """Offline test-only embedder: deterministic hash vectors, no download.

    It keeps the FROZEN model name so the index metadata contract stays
    identical, but its fingerprint is explicit and never collides with the
    real ONNX fingerprint. Unit tests use it; the real model is validated by
    ``scripts/manage_rag.py`` (and only there).
    """

    def _embed(texts: Sequence[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            raw = [byte / 255.0 for byte in digest[:16]]
            norm = math.sqrt(sum(value * value for value in raw)) or 1.0
            vectors.append([value / norm for value in raw])
        return vectors

    return RagEmbeddingModel(
        model_id=EMBEDDING_MODEL_NAME,
        fingerprint="0" * 64,
        embed=_embed,
    )


def _import_chromadb() -> Any:
    """Lazy chromadb import behind the single dependency gate."""

    try:
        import chromadb
    except ImportError as error:  # pragma: no cover - exercised via monkeypatch
        raise RagUnavailableError(
            "chromadb is not installed: install the [rag] extra "
            "(python -m pip install -e \".[dev,rag]\"); no fallback is invented"
        ) from error
    return chromadb


def default_embedder() -> RagEmbeddingModel:
    """chromadb's frozen ONNX ``all-MiniLM-L6-v2`` embedding function.

    The weights come from chromadb's pinned archive (its own SHA-256
    verification) cached under the chromadb model directory; this adapter
    records the SHA-256 of ``model.onnx`` as the fingerprint and freezes it
    in the collection metadata. Requires the ``[rag]`` extra
    (chromadb + onnxruntime + tokenizers); nothing is imported before the
    first call of this function.
    """

    _import_chromadb()
    from chromadb.utils import embedding_functions  # local import, after the gate

    model = embedding_functions.ONNXMiniLM_L6_V2()
    model_path = model.DOWNLOAD_PATH / _ONNX_MODEL_RELATIVE

    def _embed(texts: Sequence[str]) -> list[list[float]]:
        vectors = model(list(texts))
        return [[float(value) for value in vector] for vector in vectors]

    if not model_path.is_file():
        # First use: chromadb downloads its pinned archive and verifies its
        # SHA-256 itself; the probe embed is what materializes the weights.
        _embed(["fingerprint probe"])
    fingerprint = hashlib.sha256(model_path.read_bytes()).hexdigest()
    return RagEmbeddingModel(
        model_id=model.MODEL_NAME,
        fingerprint=fingerprint,
        embed=_embed,
    )


def create_rag_adapter_if_enabled(
    settings: Settings, config: RagToolConfig
) -> RagAdapter | None:
    """Factory used by ``build_services``: ``None`` when the RAG is disabled.

    Both switches must be true (tools.yaml ``rag.enabled`` AND the global
    ``RAG_ENABLED`` flag). Returning ``None`` imports nothing: this is the
    documented disabled-mode behavior (no Chroma, no weights).
    """

    if not (bool(config.enabled) and bool(settings.RAG_ENABLED)):
        return None
    return RagAdapter(config, Path(settings.RAG_DIR))


def rag_query_from_parsed(parsed: Any, max_chars: int) -> str:
    """Deterministic retrieval query for one parsed email (≤ ``max_chars``).

    Subject + useful text parts (HTML parts only as fallback when no text
    part exists), joined in part order, hard-truncated. Labels, rationale,
    ids and gold metadata never enter the query.
    """

    if parsed is None or max_chars <= 0:
        return ""
    chunks: list[str] = []
    subject = (getattr(parsed, "subject", None) or "").strip()
    if subject:
        chunks.append(subject)
    text_parts = [
        part.text.strip() for part in parsed.text_parts if part.text and part.text.strip()
    ]
    if not text_parts:
        text_parts = [
            part.text.strip() for part in parsed.html_parts if part.text and part.text.strip()
        ]
    chunks.extend(text_parts)
    return "\n".join(chunks)[: max(0, int(max_chars))]


class RagAdapter:
    """Public-only local Chroma index (one collection, cosine, k=3)."""

    COLLECTION_NAME = COLLECTION_NAME

    def __init__(
        self,
        config: RagToolConfig,
        index_dir: Path,
        *,
        embedder: RagEmbeddingModel | None = None,
        protected_family_groups: Iterable[str] = frozenset(),
    ) -> None:
        if config.embedding_model != EMBEDDING_MODEL_NAME:
            raise RagModelError(
                f"frozen RAG embedding model is {EMBEDDING_MODEL_NAME!r}, "
                f"config declares {config.embedding_model!r}"
            )
        self._config = config
        self._index_dir = Path(index_dir)
        self._embedder = embedder
        self._protected_family_groups = frozenset(protected_family_groups)
        self._client: Any | None = None
        self._collection: Any | None = None

    # --- public surface ------------------------------------------------------

    def add(self, cases: Iterable[RagSourceCase]) -> int:
        """Index public validated cases; idempotent per ``case_id``.

        Returns the number of NEWLY stored cases (identical re-adds are
        skipped; different content under an existing id, a second case of an
        already indexed family or an exceeded ``max_cases`` is an error).
        Gold/protected families are refused when the guard was provided.
        """

        prepared = [self._validated_case(case) for case in cases]
        if not prepared:
            return 0
        seen_ids: set[str] = set()
        seen_families: set[str] = set()
        for case in prepared:
            if case.case_id in seen_ids:
                raise RagSourceError(
                    f"case {case.case_id!r}: duplicated in the same add batch"
                )
            seen_ids.add(case.case_id)
            if case.family_group in seen_families:
                raise RagSourceError(
                    f"case {case.case_id!r}: family {case.family_group!r} appears "
                    "twice in the same add batch (one case per family)"
                )
            seen_families.add(case.family_group)

        collection = self._store()
        added = 0
        for case in prepared:
            payload = case.public_payload()
            existing = collection.get(ids=[case.case_id], include=["metadatas", "documents"])
            if existing["ids"]:
                if self._payload_differs(existing, case, payload):
                    raise RagIndexError(
                        f"case {case.case_id!r}: already indexed with different "
                        "content (idempotent add only replays identical cases)"
                    )
                continue  # identical re-add: no-op
            family_hits = collection.get(
                where={"family_group": case.family_group}, include=["metadatas"]
            )
            if family_hits["ids"]:
                raise RagIndexError(
                    f"case {case.case_id!r}: family {case.family_group!r} is already "
                    f"indexed by {family_hits['ids'][0]!r} (one case per family)"
                )
            if collection.count() >= self._config.max_cases:
                raise RagIndexError(
                    f"case {case.case_id!r}: index already holds {collection.count()} "
                    f"cases (max_cases={self._config.max_cases})"
                )
            vector = self._embedder_model().embed([case.text_excerpt])[0]
            collection.upsert(
                ids=[case.case_id],
                documents=[case.text_excerpt],
                embeddings=[vector],
                metadatas=[payload],
            )
            added += 1
        return added

    def search(
        self,
        query: str,
        exclusions: Iterable[str] | None = None,
        k: int = 3,
    ) -> list[RagCase]:
        """At most ``k`` public neighbours, one per family, never forced.

        Candidates beyond ``max_distance`` and any case whose
        ``family_group`` / ``duplicate_group`` / ``campaign_id`` is listed
        in ``exclusions`` are dropped locally; ties break by ``case_id``.
        An empty query or an empty/missing index yields ``[]``.
        """

        if not isinstance(k, int) or isinstance(k, bool):
            raise ValueError("k must be an integer")
        if k < 0:
            raise ValueError("k must be >= 0")
        text = (query or "").strip()
        if not text:
            return []
        text = text[: max(0, int(self._config.max_case_chars))]
        excluded = {item for item in (exclusions or ()) if isinstance(item, str)}

        collection = self._store()
        count = collection.count()
        if count == 0 or k == 0:
            return []
        vector = self._embedder_model().embed([text])[0]
        response = collection.query(
            query_embeddings=[vector],
            n_results=min(count, int(self._config.max_cases)),
            include=["metadatas", "documents", "distances"],
        )
        hits: list[tuple[float, str, Mapping[str, Any], str]] = []
        ids = response.get("ids") or [[]]
        distances = response.get("distances") or [[]]
        metadatas = response.get("metadatas") or [[]]
        documents = response.get("documents") or [[]]
        for index, case_id in enumerate(ids[0]):
            metadata = metadatas[0][index] if index < len(metadatas[0]) else {}
            document = documents[0][index] if index < len(documents[0]) else ""
            distance = float(distances[0][index])
            if distance > float(self._config.max_distance):
                continue
            hits.append((distance, str(case_id), metadata, str(document)))
        hits.sort(key=lambda item: (item[0], item[1]))

        neighbours: list[RagCase] = []
        seen_families: set[str] = set()
        model_id = self.embedding_model_id()
        for distance, case_id, metadata, document in hits:
            if len(neighbours) >= k:
                break
            family = str(metadata.get("family_group", ""))
            duplicate = str(metadata.get("duplicate_group", ""))
            campaign = metadata.get("campaign_id")
            if family in excluded or duplicate in excluded or campaign in excluded:
                continue
            if family in seen_families:
                continue  # one neighbour per family_group (docs/corpus.md §7.6)
            seen_families.add(family)
            neighbours.append(
                RagCase(
                    case_id=case_id,
                    public_source_url=str(metadata["public_source_url"]),
                    dataset=str(metadata["dataset"]),
                    record_sha256=str(metadata["record_sha256"]),
                    validated_label=metadata["validated_label"],  # type: ignore[arg-type]
                    analyst_validation_ref=str(metadata["analyst_validation_ref"]),
                    campaign_id=str(campaign) if campaign is not None else None,
                    duplicate_group=duplicate,
                    family_group=family,
                    text_excerpt=document,
                    analyst_rationale=str(metadata.get("analyst_rationale", "")),
                    distance=distance,
                    embedding_model_id=model_id,
                    is_public=True,
                    split="rag_reference",
                )
            )
        return neighbours

    def clear(self) -> None:
        """Delete the collection content; the next call reopens an empty index."""

        self._store()
        self._client.delete_collection(self.COLLECTION_NAME)  # type: ignore[union-attr]
        self._client = None
        self._collection = None

    def count(self) -> int:
        """Number of indexed public cases (0 on a missing/empty index)."""

        return self._store().count()

    def describe(self) -> dict[str, Any]:
        """Index description for receipts/manifests (no case content)."""

        collection = self._store()
        return {
            "collection": self.COLLECTION_NAME,
            "index_dir": str(self._index_dir),
            "count": collection.count(),
            "distance_space": "cosine",
            "embedding_model_id": self.embedding_model_id(),
            "embedding_model_sha256": self._embedder_model().fingerprint,
            "max_cases": int(self._config.max_cases),
            "k": int(self._config.k),
            "max_distance": float(self._config.max_distance),
        }

    def embedding_model_id(self) -> str:
        """Qualified embedding id recorded on every produced ``RagCase``."""

        return self._embedder_model().qualified_id

    # --- internals -----------------------------------------------------------

    def _validated_case(self, case: RagSourceCase) -> RagSourceCase:
        """Structural refusals required by the frozen source contract."""

        if not isinstance(case, RagSourceCase):
            raise RagSourceError("add() expects RagSourceCase records")
        if case.is_public is not True:
            raise RagSourceError(f"case {case.case_id!r}: is_public must be True")
        if case.split != "rag_reference":
            raise RagSourceError(
                f"case {case.case_id!r}: split {case.split!r} refused "
                "(gold/dev/test records are never indexed)"
            )
        if not case.text_excerpt.strip():
            raise RagSourceError(f"case {case.case_id!r}: empty text excerpt")
        if len(case.text_excerpt) > self._config.max_case_chars:
            raise RagSourceError(
                f"case {case.case_id!r}: text_excerpt exceeds "
                f"max_case_chars={self._config.max_case_chars}"
            )
        if case.family_group in self._protected_family_groups:
            raise RagSourceError(
                f"case {case.case_id!r}: family {case.family_group!r} is a protected "
                "gold family and must never be indexed"
            )
        return case

    @staticmethod
    def _payload_differs(
        existing: Mapping[str, Any], case: RagSourceCase, payload: Mapping[str, Any]
    ) -> bool:
        stored_document = (existing.get("documents") or [""])[0]
        stored_metadata = (existing.get("metadatas") or [{}])[0] or {}
        if stored_document != case.text_excerpt:
            return True
        if stored_metadata.get("campaign_id") is None and case.campaign_id is None:
            comparable = {key: value for key, value in payload.items() if key != "campaign_id"}
        else:
            comparable = dict(payload)
        return any(stored_metadata.get(key) != value for key, value in comparable.items())

    def _embedder_model(self) -> RagEmbeddingModel:
        if self._embedder is None:
            self._embedder = default_embedder()
        return self._embedder

    def _store(self) -> Any:
        if self._collection is None:
            chromadb = _import_chromadb()
            embedder = self._embedder_model()
            self._index_dir.mkdir(parents=True, exist_ok=True)
            settings = chromadb.config.Settings(anonymized_telemetry=False)
            self._client = chromadb.PersistentClient(
                path=str(self._index_dir), settings=settings
            )
            metadata = {
                "hnsw:space": "cosine",
                "embedding_model_id": embedder.qualified_id,
                "embedding_model_sha256": embedder.fingerprint,
            }
            existing = {item.name for item in self._client.list_collections()}
            if self.COLLECTION_NAME in existing:
                collection = self._client.get_collection(self.COLLECTION_NAME)
                stored = collection.metadata or {}
                for key in ("embedding_model_id", "embedding_model_sha256"):
                    if stored.get(key) != metadata[key]:
                        raise RagModelError(
                            f"embedding model mismatch (stored {stored.get(key)!r}): "
                            f"the frozen index expects {metadata[key]!r}; the index "
                            "must be rebuilt (clear + add), never mixed"
                        )
                self._collection = collection
            else:
                self._collection = self._client.create_collection(
                    name=self.COLLECTION_NAME,
                    metadata=metadata,
                )
        return self._collection


__all__ = [
    "COLLECTION_NAME",
    "EMBEDDING_MODEL_NAME",
    "RagAdapter",
    "RagEmbeddingModel",
    "RagError",
    "RagIndexError",
    "RagModelError",
    "RagSourceCase",
    "RagSourceError",
    "RagUnavailableError",
    "create_rag_adapter_if_enabled",
    "default_embedder",
    "deterministic_stub_embedder",
    "rag_query_from_parsed",
]
