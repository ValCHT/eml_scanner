#!/usr/bin/env python3
"""TICKET-14 — dev harness smoke evaluation and exact offline recompute (G6).

Operator trajectory 2026-09-21 (accelerated agentic path): G6 is a
HARNESS-validation gate, not a performance benchmark. No full dev benchmark
before T19E — T15/T16 and the T19A–T19D development steps use bounded
samples/smokes only; the first full benchmark is T19E
(`--sample-profile full` capability preserved but NOT executed before it).

Live mode (``--split dev --mode live --variant baseline --sample-profile smoke``):

1. loads the frozen evaluation configuration and verifies the experiment
   lock (hashes of gate/policy/tools configs, prompts, schemas, gold_dev);
   any drift fails the run instead of silently measuring a moved baseline;
2. loads and fully validates ALL 83 ``corpus/gold/gold_dev.jsonl`` records —
   closed GoldRecord schema, forbidden content keys refused recursively,
   resolved ``raw_path`` under ``corpus/raw/**``, recomputed SHA-256 vs
   ``raw_sha256`` and ``email_sha256 == raw_sha256`` — BEFORE any LLM or
   external-tool call; a mismatch is a loud failure, never a silent sample
   drop;
3. selects the deterministic representative smoke (one lexicographically
   first ``sample_id`` per dev label with support>0; menace has zero
   support and is never fabricated) and runs live calls ONLY for the
   selected records (``--sample-profile full`` = the complete 83-record
   capability, reserved for TICKET-19E);
4. runs the frozen pipeline for every selected email and archives the
   authentic per-sample report under ``<out>/<run_id>/report.json``;
5. for COMPLEX emails runs the A/B/C control: A is the shared INTERNAL of
   the nominal run, B is an XHIGH control call with parser-internal
   evidence only (TOOL_STATUS explicitly marks the ablation, RAG empty, no
   pixels), C is the nominal FINAL with the real external bundle; the FINAL
   input audits (docs/contracts.md §2.6.1) are validated BEFORE any B−A /
   C−B comparison is published;
6. writes exactly one evaluation row per ``sample_id``, the deterministic
   metrics (``src.metrics``), the confusion matrix CSV, a manifest and a
   human-readable report. Failures/outages stay in every denominator.
   Smoke results are DIAGNOSTIC ONLY (``measurement_scope=smoke``,
   ``performance_claims_allowed=false``): never presented as a performance
   baseline, representative Macro-F1 or statistical validation.

Recompute mode (``--mode recompute --from-run <run> --out <dir>``):

performs NO provider call and NO external network access; it reloads the
archived gold_dev records, evaluation rows and authentic per-sample reports
and recomputes the metrics deterministically. For a smoke run it reproduces
exactly the archived selected rows and verifies their identity against the
deterministic selection (no ``len(rows)==83`` requirement); for a
``full_dev_baseline`` run the complete row set is still required. The
result must equal the live metrics exactly (metrics carry no wall-clock
data); only the recompute manifest differs (explicit recomputation
metadata, original observation timestamps preserved).

Paired variant mode (TICKET-15, docs/evaluation.md §8.7):
``--variant rag --paired-with <archived baseline run>`` runs the SAME
bounded deterministic smoke through the frozen pipeline with the public RAG
context enabled IN MEMORY (the frozen ``configs/tools.yaml`` is never
rewritten) and writes the paired diagnostic comparison. The archived
baseline run is read only: its files are never modified, its rows/reports
are never replayed, and the exact ``sample_id`` identity + denominators are
verified before any provider call (missing/extra row = FAIL). The result
stays diagnostic (``measurement_scope=smoke``,
``performance_claims_allowed=false``, INCONCLUSIVE valid): the RAG
ablation is an experimental closure, never a performance claim.

Security: no secret is ever read or printed (settings expose presence
booleans only); gold_test.jsonl is NEVER opened by this script — the
terminal test evaluation belongs to a later authorized ticket; email
content only lives inside the per-run restricted artifacts under ``runs/``
(git-ignored), never in the evaluation rows.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for _path in (str(SCRIPTS_DIR), str(PROJECT_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import build_corpus  # scripts/build_corpus.py: GoldRecord contract + raw loader

from pydantic import BaseModel, ConfigDict, ValidationError

from src.config import (
    GateConfig,
    PolicyConfig,
    Settings,
    ToolsConfig,
    load_settings,
    load_yaml_config,
)
from src.evidence import assess_final, merge_evidence
from src.graph import build_graph, build_services, config_sha256
from src.llm import LunaClient
from src.metrics import (
    LABELS,
    estimate_cost_usd,
    evaluate as evaluate_metrics,
    latency_stats,
    paired_variant_block,
    validate_control_audits,
)
from src.prompts import canonical_bytes
from src.state import EmailTriageState, Enrichment, ToolResult, new_state
from src.tools.rag import (
    RagAdapter,
    RagError,
    RagUnavailableError,
    create_rag_adapter_if_enabled,
)
from src.verify import compute_verdict_confidence

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BLOCKED = 2

#: The TICKET-14 dev workflow never opens gold_test.jsonl (operator rule).
FORBIDDEN_SPLIT = "test"

#: Variants of the frozen pipeline (docs/evaluation.md §8.7). TICKET-15
#: implements the RAG paired ablation; TICKET-16 will add the vision one.
BASELINE_VARIANT = "baseline"
RAG_VARIANT = "rag"

ABLATION_TOOL_REASON = "ablation_control_b_no_external_evidence"

#: Sample profiles (operator amendment 2026-09-21): no full dev benchmark
#: before TICKET-19E. ``smoke`` = deterministic representative harness smoke;
#: ``full`` = complete gold_dev evaluation capability, reserved for T19E.
SMOKE_PROFILE = "smoke"
FULL_PROFILE = "full"

SAMPLE_SELECTION_RULE = (
    "deterministic_stratified_smoke_v1: for each dev label with support>0 "
    "in fixed taxonomy order (menace excluded, support=0 — nothing "
    "fabricated), select the lexicographically first sample_id; exactly "
    "one record per label; full gold metadata/raw integrity is still "
    "validated for all 83 records before any live call; results are "
    "harness diagnostics only (measurement_scope=smoke, "
    "performance_claims_allowed=false); the first full benchmark is "
    "TICKET-19E"
)

#: Exact filename of the archived FINAL validation rejects (assess_final).
FINAL_REJECT_FILE = "final_validation_reject.json"

#: Early-abort threshold for a FULL-corpus run (TICKET-19E scope): a hard
#: endpoint outage fails every INTERNAL attempt from the first record, and
#: aborting avoids burning the corpus. The bounded smoke NEVER aborts on
#: provider outcomes (operator amendment 2026-09-21): a timeout/unavailable is
#: an honest archived row, not a harness failure.
CONSECUTIVE_INFRA_FAILURE_LIMIT = 5

VALID_EXIT_CODES = {EXIT_OK, EXIT_FAIL, EXIT_BLOCKED}


class GoldTestAccessRefused(RuntimeError):
    """Refusal to open gold_test.jsonl outside its authorized later ticket."""


class ExperimentLockError(RuntimeError):
    """The frozen experiment configuration no longer matches the lock."""


class PairedRunError(RuntimeError):
    """The archived paired run cannot be paired with the current run (§8.7)."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class EvaluationConfig(BaseModel):
    """Strict ``configs/evaluation.yaml`` model (extra keys refused)."""

    model_config = ConfigDict(extra="forbid")

    version: int
    label_order: list[str]
    split_files: dict[str, str]
    split_policy: dict[str, Any]
    source_profile_mapping: dict[str, str]
    pricing_snapshot: dict[str, Any]
    latency: dict[str, Any]
    abc: dict[str, Any]
    published_limitations: list[str]


def load_evaluation_config(path: Path) -> EvaluationConfig:
    config = load_yaml_config(path, EvaluationConfig)
    assert isinstance(config, EvaluationConfig)
    if tuple(config.label_order) != LABELS:
        raise ExperimentLockError(
            f"evaluation.yaml label_order {config.label_order!r} differs from "
            f"the fixed taxonomy {LABELS!r}"
        )
    return config


def load_experiment_lock(path: Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ExperimentLockError(f"{path}: experiment lock must be a JSON object")
    return data


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_experiment_lock(lock: Mapping[str, Any]) -> list[str]:
    """Compare the lock's frozen-input hashes with the current files.

    Returns the list of drift problems (empty = the frozen baseline is
    intact). The lock covers every input the measurement depends on: model
    binding, reasoning configuration, prompts, schemas, gate/policy/tools
    configuration, requirements.lock, evaluation.yaml and gold_dev.jsonl.
    """

    problems: list[str] = []
    runtime = lock.get("runtime") or {}
    settings = load_settings()
    model = runtime.get("model")
    if model and settings.LITELLM_MODEL != model:
        problems.append(
            f"runtime model changed: lock {model!r} vs settings {settings.LITELLM_MODEL!r}"
        )
    chat_url = runtime.get("chat_url")
    if chat_url and settings.LITELLM_CHAT_URL != chat_url:
        problems.append(
            f"runtime endpoint changed: lock {chat_url!r} vs settings "
            f"{settings.LITELLM_CHAT_URL!r}"
        )
    reasoning = runtime.get("reasoning") or {}
    if reasoning.get("internal") != "medium" or reasoning.get("final") != "xhigh":
        problems.append("reasoning configuration in lock is not internal=medium/final=xhigh")
    for section, file_path in (
        ("prompts_internal", PROJECT_ROOT / "prompts" / "internal_assessment.txt"),
        ("prompts_final", PROJECT_ROOT / "prompts" / "final_assessment.txt"),
        ("schema_assessment", PROJECT_ROOT / "schemas" / "assessment.schema.json"),
        ("schema_triage_report", PROJECT_ROOT / "schemas" / "triage_report.schema.json"),
        ("config_gate", PROJECT_ROOT / "configs" / "gate.yaml"),
        ("config_policy", PROJECT_ROOT / "configs" / "policy.yaml"),
        ("config_tools", PROJECT_ROOT / "configs" / "tools.yaml"),
        ("requirements_lock", PROJECT_ROOT / "requirements.lock"),
        ("evaluation_config", PROJECT_ROOT / "configs" / "evaluation.yaml"),
        ("gold_dev", PROJECT_ROOT / "corpus" / "gold" / "gold_dev.jsonl"),
    ):
        recorded = lock.get("hashes", {}).get(section)
        if not recorded:
            problems.append(f"experiment lock missing hash for {section}")
            continue
        if not file_path.is_file():
            problems.append(f"frozen input missing: {file_path}")
            continue
        actual = _file_sha256(file_path)
        if actual != recorded:
            problems.append(
                f"frozen input changed since the lock: {section} "
                f"({file_path.name}); the baseline is no longer the locked one"
            )
    gate_thresholds = lock.get("gate_thresholds") or {}
    gate_config = load_yaml_config(PROJECT_ROOT / "configs" / "gate.yaml", GateConfig)
    if (
        gate_config.min_confidence != gate_thresholds.get("min_confidence")
        or gate_config.min_margin != gate_thresholds.get("min_margin")
    ):
        problems.append("gate thresholds differ from the locked BASELINE V0 values")
    return problems



# ---------------------------------------------------------------------------
# Gold loading and full pre-call validation (docs/contracts.md §2.8)
# ---------------------------------------------------------------------------


def gold_path_for_split(config: EvaluationConfig, split: str) -> Path:
    """Split file path; the test split is refused outside its later ticket."""

    if split == FORBIDDEN_SPLIT:
        raise GoldTestAccessRefused(
            "gold_test.jsonl must not be opened by the TICKET-14 dev "
            "workflow (internal POC validation partition, read only by the "
            "authorized terminal test ticket); development uses gold_dev only"
        )
    relative = config.split_files.get(split)
    if not relative:
        raise ValueError(f"evaluation.yaml has no split file for split {split!r}")
    path = PROJECT_ROOT / relative
    if not path.is_file():
        raise FileNotFoundError(f"gold partition file missing: {path}")
    return path


def load_gold_records(
    config: EvaluationConfig, split: str
) -> tuple[list[dict[str, Any]], Path]:
    """Load one gold partition with the FULL closed-schema validation.

    Every record is checked (fail-closed, loud): exact GoldRecord field set,
    no forbidden content key anywhere (recursive, case-insensitive, even
    null/empty), ``label_status=confirmed``, taxonomy label, split, hash
    format, ``email_sha256 == raw_sha256`` and the Gold-AI reviewer ref.
    Records are sorted by ``sample_id`` for a deterministic run order.
    """

    path = gold_path_for_split(config, split)
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise build_corpus.GoldValidationError(
                        f"{path}: gold record is not a JSON object"
                    )
                rows.append(row)
    if not rows:
        raise build_corpus.GoldValidationError(f"{path}: empty gold partition")
    build_corpus.validate_gold_records(rows, expected_splits=(split,))
    rows.sort(key=lambda row: str(row["sample_id"]))
    return rows, path


def validate_gold_raw_files(rows: list[dict[str, Any]]) -> tuple[dict[str, bytes], list[str]]:
    """Resolve raw_path, reload the bytes and verify every hash.

    Runs BEFORE any LLM or external-tool call: missing file, hash mismatch,
    ``raw_path`` escaping ``corpus/raw/**`` (symlink-aware) or a null/unknown
    field abort the evaluation with a loud error. Returns the verified bytes
    per sample_id (exact message bytes, never re-encoded).

    This integrity check ALWAYS covers ALL provided records (the complete
    gold_dev partition, even when the live scope is the 5-record smoke).
    """

    loader = build_corpus._RawLoader(PROJECT_ROOT)
    verified: dict[str, bytes] = {}
    failures: list[str] = []
    for row in rows:
        sample_id = str(row["sample_id"])
        try:
            data = loader.verified_bytes(
                sample_id,
                str(row["raw_path"]),
                str(row["raw_sha256"]),
                str(row["input_format"]),
            )
        except build_corpus.GoldValidationError as error:
            failures.append(f"{sample_id}: {error}")
            continue
        if row["email_sha256"] != row["raw_sha256"]:
            failures.append(f"{sample_id}: email_sha256 must equal raw_sha256")
            continue
        verified[sample_id] = data
    return verified, failures


def select_smoke_sample(gold_rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic representative smoke: one record per supported label.

    For each dev label with support>0 in fixed taxonomy order, the
    lexicographically first ``sample_id`` is selected. ``menace`` has zero
    support in this POC: nothing is fabricated for it. The result is the
    bounded T14 smoke set (5 records today); the complete 83-record
    capability stays untouched for TICKET-19E.
    """

    by_label: dict[str, list[Mapping[str, Any]]] = {}
    for row in gold_rows:
        by_label.setdefault(str(row["normalized_label"]), []).append(row)
    selected: list[dict[str, Any]] = []
    for label in LABELS:
        candidates = sorted(by_label.get(label, []), key=lambda row: str(row["sample_id"]))
        if not candidates:
            continue  # zero support: nothing fabricated
        selected.append(dict(candidates[0]))
    return selected


def derive_source_profile(row: Mapping[str, Any], config: EvaluationConfig) -> str:
    """Source profile from dataset provenance, never from message content."""

    public_source = row.get("public_source")
    mapping = config.source_profile_mapping
    if public_source is True:
        profile = mapping.get("public_source_true")
    elif public_source is False:
        profile = mapping.get("public_source_false")
    else:
        profile = None
    if profile not in ("public_corpus", "private_authorized"):
        raise ValueError(
            f"sample {row.get('sample_id')!r}: cannot derive a valid source "
            f"profile from public_source={public_source!r}"
        )
    return profile


# ---------------------------------------------------------------------------
# Paired variant interface (docs/evaluation.md §8.7, TICKET-15)
# ---------------------------------------------------------------------------


def _project_relative(path: Path) -> str:
    """Project-relative display path when possible (never fails loudly)."""

    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        return str(path)


@dataclass(frozen=True)
class PairedBaseline:
    """Read-only view of the archived baseline run used for pairing (§8.7).

    The paired run is LOADED, never replayed and never written: its rows and
    reports stay untouched provenance. ``manifest_sha256`` /
    ``predictions_sha256`` are the exact bytes read (recorded in the paired
    artifact so a later reader can prove which archived run was compared).
    """

    run_dir: Path
    manifest: dict[str, Any]
    rows: list[dict[str, Any]]
    manifest_sha256: str
    predictions_sha256: str

    @property
    def selected_sample_ids(self) -> list[str]:
        return [str(value) for value in self.manifest["selected_sample_ids"]]

    @property
    def by_sample_id(self) -> dict[str, dict[str, Any]]:
        return {str(row["sample_id"]): row for row in self.rows}


def load_paired_baseline(run_dir: Path, *, expected_scope: str) -> PairedBaseline:
    """Load an archived baseline run READ-ONLY and verify its identity.

    Fails closed (``PairedRunError``) on a missing run, a non-baseline
    variant, a split/scope/selection-rule mismatch, a row set that does not
    reproduce ``selected_sample_ids`` exactly (missing or extra row = FAIL)
    or duplicated sample ids. No file is ever written.
    """

    if not run_dir.is_dir():
        raise PairedRunError(f"paired run directory missing: {run_dir}")
    manifest_path = run_dir / "manifest.json"
    predictions_path = run_dir / "predictions.jsonl"
    if not manifest_path.is_file() or not predictions_path.is_file():
        raise PairedRunError(
            f"paired run {run_dir} is not an archived evaluation run "
            "(manifest.json/predictions.jsonl missing)"
        )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PairedRunError(f"paired run manifest unreadable: {error}") from error
    if not isinstance(manifest, dict):
        raise PairedRunError("paired run manifest is not a JSON object")

    problems: list[str] = []
    if manifest.get("variant") != BASELINE_VARIANT:
        problems.append(
            f"variant must be {BASELINE_VARIANT!r} (got {manifest.get('variant')!r})"
        )
    if manifest.get("split") != "dev":
        problems.append(f"split must be 'dev' (got {manifest.get('split')!r})")
    if manifest.get("measurement_scope") != expected_scope:
        problems.append(
            "measurement_scope must match the current run "
            f"({expected_scope!r} vs {manifest.get('measurement_scope')!r})"
        )
    if expected_scope == "smoke" and manifest.get(
        "performance_claims_allowed"
    ) is not False:
        problems.append("a smoke paired run must archive performance_claims_allowed=false")
    if manifest.get("sample_selection_rule") != SAMPLE_SELECTION_RULE:
        problems.append("sample_selection_rule differs from the deterministic smoke rule")
    selected = manifest.get("selected_sample_ids")
    if not isinstance(selected, list) or not selected:
        problems.append("selected_sample_ids must be a non-empty list")

    rows: list[dict[str, Any]] = []
    try:
        with predictions_path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise PairedRunError("paired run row is not a JSON object")
                rows.append(row)
    except (OSError, json.JSONDecodeError) as error:
        raise PairedRunError(f"paired run predictions unreadable: {error}") from error
    if not rows:
        problems.append("paired run has no archived rows")
    ids = [str(row.get("sample_id")) for row in rows]
    if len(set(ids)) != len(ids):
        problems.append("paired run rows contain duplicated sample_id values")
    if isinstance(selected, list) and selected and sorted(ids) != sorted(
        str(value) for value in selected
    ):
        problems.append(
            "paired run rows do not reproduce its selected_sample_ids exactly "
            "(missing or extra row)"
        )
    if manifest.get("sample_count") != len(rows):
        problems.append(
            f"paired manifest sample_count {manifest.get('sample_count')!r} != "
            f"{len(rows)} archived rows"
        )
    for row in rows:
        sample_id = row.get("sample_id")
        if row.get("variant") != BASELINE_VARIANT:
            problems.append(f"row {sample_id!r}: variant must be {BASELINE_VARIANT!r}")
            break
        if row.get("split") != "dev":
            problems.append(f"row {sample_id!r}: split must be 'dev'")
            break
        if row.get("measurement_scope") != expected_scope:
            problems.append(f"row {sample_id!r}: measurement_scope mismatch")
            break
    if problems:
        raise PairedRunError("paired run invalid: " + "; ".join(problems))
    return PairedBaseline(
        run_dir=run_dir,
        manifest=manifest,
        rows=rows,
        manifest_sha256=_file_sha256(manifest_path),
        predictions_sha256=_file_sha256(predictions_path),
    )


def verify_paired_selection(
    paired: PairedBaseline, selected_rows: list[Mapping[str, Any]]
) -> None:
    """Exact sample-id identity between the paired run and the current selection.

    The paired rows must describe the SAME gold records (same ``sample_id``,
    same label, same raw bytes hash): a sample_id that names a different
    record makes the comparison meaningless and is refused before any call.
    """

    current_ids = sorted(str(row["sample_id"]) for row in selected_rows)
    paired_ids = sorted(paired.selected_sample_ids)
    if current_ids != paired_ids:
        raise PairedRunError(
            "sample-id identity mismatch: current deterministic selection "
            f"{current_ids} differs from the paired run selection {paired_ids}"
        )
    gold_by_id = {str(row["sample_id"]): row for row in selected_rows}
    for row in paired.rows:
        sample_id = str(row["sample_id"])
        gold = gold_by_id[sample_id]
        if str(row.get("label")) != str(gold["normalized_label"]):
            raise PairedRunError(
                f"sample {sample_id}: paired label {row.get('label')!r} != gold "
                f"label {gold['normalized_label']!r}"
            )
        if str(row.get("raw_sha256")) != str(gold["raw_sha256"]):
            raise PairedRunError(
                f"sample {sample_id}: paired raw_sha256 differs from the gold record"
            )


@dataclass(frozen=True)
class RagAblation:
    """Effective RAG-enabled configuration + the validated adapter (§8.7)."""

    effective_settings: Settings
    effective_tools: ToolsConfig
    adapter: RagAdapter
    description: dict[str, Any]


def prepare_rag_ablation(settings: Settings, tools: ToolsConfig) -> RagAblation:
    """Build the effective RAG-enabled configuration and the ONE adapter.

    The frozen ``configs/tools.yaml`` keeps ``rag.enabled=false`` (the G6
    baseline file is never rewritten, so its lock hash stays valid); the
    ablation applies the capability IN MEMORY for this run only and the
    manifest records the explicit overrides. The adapter verifies the frozen
    embedding fingerprint on open and its index must be non-empty: an empty
    index is refused instead of silently measuring an always-empty context.
    """

    rag_dir = Path(settings.RAG_DIR)
    if not rag_dir.is_absolute():
        rag_dir = (PROJECT_ROOT / rag_dir).resolve()
    effective_settings = settings.model_copy(
        update={"RAG_ENABLED": True, "RAG_DIR": rag_dir}
    )
    effective_tools = tools.model_copy(
        update={"rag": tools.rag.model_copy(update={"enabled": True})}
    )
    adapter = create_rag_adapter_if_enabled(effective_settings, effective_tools.rag)
    if adapter is None:  # pragma: no cover - both switches are forced true above
        raise RagError("RAG ablation factory returned no adapter")
    count = adapter.count()
    description = adapter.describe()
    if count <= 0:
        raise RagError(
            f"public RAG index is empty ({description['index_dir']}): build it "
            "first (python scripts/manage_rag.py add --input "
            "corpus/rag/public_cases.jsonl)"
        )
    return RagAblation(
        effective_settings=effective_settings,
        effective_tools=effective_tools,
        adapter=adapter,
        description=description,
    )


# ---------------------------------------------------------------------------
# Frozen pipeline runner (same nodes/graph as run_email, state kept)
# ---------------------------------------------------------------------------


def run_nominal_pipeline(
    settings: Settings,
    email_path: Path,
    source_profile: str,
    *,
    tools_override: ToolsConfig | None = None,
    rag_adapter: RagAdapter | None = None,
    rag_exclusions: set[str] | None = None,
    current_duplicate_group: str | None = None,
    current_family_group: str | None = None,
    current_campaign_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the frozen sequential StateGraph for one email.

    Mirrors ``src.graph.run_email`` exactly (same configs, same service
    building, same graph, same report archiving under
    ``RUNS_DIR/<run_id>/report.json``) but keeps the FULL final state so the
    shared INTERNAL assessment (A) and the merged evidence bundle are
    available to the A/B/C control and audit.

    ``tools_override`` / ``rag_adapter`` are the paired-ablation seam
    (§8.7): the run executes under the effective configuration and reuses
    the already-validated adapter; the frozen baseline call site passes
    neither and is byte-identical to the T14 harness.
    """

    tools = load_yaml_config(Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig)
    if tools_override is not None:
        tools = tools_override
    gate = load_yaml_config(Path(settings.CONFIG_DIR) / "gate.yaml", GateConfig)
    policy = load_yaml_config(Path(settings.CONFIG_DIR) / "policy.yaml", PolicyConfig)
    started = time.monotonic()
    state = new_state(email_path, source_profile, config_sha256(settings, tools, gate, policy))  # type: ignore[arg-type]
    services = build_services(
        settings,
        source_profile=source_profile,  # type: ignore[arg-type]
        run_id=state.run_id,
        started_monotonic=started,
        tools_override=tools_override,
        rag=rag_adapter,
        rag_exclusions=rag_exclusions,
        current_duplicate_group=current_duplicate_group,
        current_family_group=current_family_group,
        current_campaign_id=current_campaign_id,
    )
    graph = build_graph(services)
    final_state = graph.invoke(state, config={"configurable": {"thread_id": state.run_id}})
    report_path = final_state.get("report_path") if isinstance(final_state, dict) else None
    if not isinstance(report_path, str) or not Path(report_path).is_file():
        raise RuntimeError("pipeline completed without an archived report path")
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise RuntimeError("archived report is not a JSON object")
    return report, final_state


# ---------------------------------------------------------------------------
# A/B/C control (variant baseline, COMPLEX samples, docs/evaluation.md §8.3)
# ---------------------------------------------------------------------------


def ablation_tool_results() -> Enrichment:
    """Honest TOOL_STATUS placeholders for the B ablation control.

    No external result is fabricated: the control simply did not execute the
    tools, and every entry says so explicitly (``skipped`` + ablation reason,
    ``mode="none"``, zero requests, no response reference). This is what
    makes the B TOOL_STATUS distinguishable from both an empty status list
    and a real tool execution.
    """

    return Enrichment(
        virustotal=[
            ToolResult(
                tool="virustotal",
                status="skipped",
                reason=ABLATION_TOOL_REASON,
                mode="none",
            )
        ],
        opencti=[
            ToolResult(
                tool="opencti",
                status="skipped",
                reason=ABLATION_TOOL_REASON,
                mode="none",
            )
        ],
        urlscan=[
            ToolResult(
                tool="urlscan",
                status="skipped",
                reason=ABLATION_TOOL_REASON,
                mode="none",
            )
        ],
        rag=[],
    )


def run_control_b(
    settings: Settings,
    final_state: Mapping[str, Any],
    capture_dir: Path,
    pricing: Mapping[str, Any],
) -> dict[str, Any]:
    """Variant B: XHIGH FINAL call with internal evidence only.

    Reuses the SHARED internal assessment (A) of the nominal run — never a
    second INTERNAL call. Evidence/observable registries come from
    ``merge_evidence(parsed, None)`` (parser INTERNE entries only), RAG is
    empty, no pixel is attached, and TOOL_STATUS carries the explicit
    ablation markers. The client archives the exact-bytes input audits into
    the dedicated ``responses_control_b`` directory so the nominal FINAL
    audits are never overwritten.
    """

    parsed = final_state.get("parsed")
    internal = final_state.get("internal")
    payload: dict[str, Any] = {
        "attempted": False,
        "reason_not_attempted": None,
        "verdict": None,
        "confidence": None,
        "probabilities": None,
        "call": None,
        "latency_ms": None,
        "capture_dir": capture_dir.name,
        "cost_usd": None,
        "cost_status": "unknown",
    }
    if parsed is None:
        payload["reason_not_attempted"] = "parsed_none_nominal_parse_failed"
        return payload
    capture_dir.mkdir(parents=True, exist_ok=True)
    evidence_b, observables_b, _visuals = merge_evidence(parsed, None)
    client_b = LunaClient(
        settings,
        phase="final",
        capture_dir=capture_dir,
        persist_request_body=False,
    )
    started = time.monotonic()
    candidate, record = assess_final(
        parsed,
        internal,
        evidence_b,
        [],
        client_b,
        observables=observables_b,
        tool_results=ablation_tool_results(),
        run_artifacts={"capture_dir": capture_dir},
    )
    latency_ms = round((time.monotonic() - started) * 1000.0, 3)
    payload["attempted"] = True
    payload["latency_ms"] = latency_ms
    payload["call"] = record.model_dump(mode="json")
    cost, cost_status = estimate_cost_usd(record.model_dump(mode="json"), pricing)
    payload["cost_usd"] = cost
    payload["cost_status"] = cost_status
    if candidate is not None:
        probabilities = candidate.model_dump()["probabilities"]
        verdict, confidence = compute_verdict_confidence(probabilities)
        payload["verdict"] = verdict
        payload["confidence"] = confidence
        payload["probabilities"] = {key: float(value) for key, value in probabilities.items()}
    else:
        payload["reason_not_attempted"] = None
        payload["call_status"] = record.status
    return payload


def read_final_audits(capture_dir: Path) -> list[dict[str, Any]]:
    """Every archived §2.6.1 FINAL input audit of one capture directory."""

    audits: list[dict[str, Any]] = []
    if not capture_dir.is_dir():
        return audits
    for path in sorted(capture_dir.glob("final_attempt_*.input_audit.json")):
        try:
            audit = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(audit, dict):
            audits.append(audit)
    return audits


def count_final_rejects(capture_dir: Path) -> tuple[int, int, int]:
    """Pre-verifier proposal counters from the archived validation rejects.

    Returns ``(rejected_candidates, proposals_total, proposals_invalid)``
    where a proposal is every reference the FINAL model emitted and an
    invalid proposal is a reference outside the registry actually sent.
    Only the REJECTED candidates are archived by ``assess_final``; accepted
    candidate proposals are counted from the validated assessment itself.
    """

    rejects = 0
    proposals_total = 0
    proposals_invalid = 0
    if not capture_dir.is_dir():
        return rejects, proposals_total, proposals_invalid
    for path in capture_dir.glob(FINAL_REJECT_FILE):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        rejects += 1
        issues = data.get("issues") or []
        candidate = data.get("candidate") or {}
        proposals_total += count_candidate_proposals(candidate if isinstance(candidate, Mapping) else {})
        for issue in issues:
            text = str(issue)
            if "unknown evidence ID" in text or "unknown observable ID" in text:
                proposals_invalid += 1
    return rejects, proposals_total, proposals_invalid


def count_candidate_proposals(candidate: Mapping[str, Any] | None) -> int:
    """Every ID reference proposed by one Assessment (accepted candidates)."""

    if candidate is None:
        return 0
    total = len(candidate.get("observations") or [])
    for inference in candidate.get("inferences") or []:
        total += len(inference.get("evidence_ids") or [])
    for assessment in candidate.get("observable_assessments") or []:
        total += 1  # the observable itself is proposed for categorization
        total += len(assessment.get("evidence_ids") or [])
    total += len(candidate.get("decisive_evidence_ids") or [])
    return total


def count_attempt_refusals(capture_dirs: list[Path]) -> int:
    """Number of refused attempts across the given capture directories."""

    refusals = 0
    for capture_dir in capture_dirs:
        if not capture_dir.is_dir():
            continue
        for path in capture_dir.glob("attempt_*_error.txt"):
            try:
                first_line = path.read_text(encoding="utf-8").splitlines()[0]
            except (OSError, IndexError):
                continue
            if first_line.startswith("LLMRefused"):
                refusals += 1
    return refusals


# ---------------------------------------------------------------------------
# Evaluation row (exactly one row per sample_id; no email content)
# ---------------------------------------------------------------------------


def build_evaluation_row(
    row: Mapping[str, Any],
    report: Mapping[str, Any],
    final_state: Mapping[str, Any],
    report_file: Path,
    control_b: Mapping[str, Any] | None,
    pricing: Mapping[str, Any],
    variant: str,
    split: str,
    measurement_scope: str,
) -> dict[str, Any]:
    """One authentic evaluation row with its full provenance."""

    report_rel = report_file.relative_to(PROJECT_ROOT)
    report_dir_rel = Path(report_file).parent.name  # relative to the run root
    internal = final_state.get("internal")
    parsed = final_state.get("parsed")
    evidence_registry = final_state.get("evidence") or {}
    provenance_counts = {"INTERNE": 0, "OSINT": 0, "SANDBOX": 0}
    for entry in evidence_registry.values():
        provenance = getattr(entry, "provenance", None)
        if provenance in provenance_counts:
            provenance_counts[provenance] += 1
    bundle_external = provenance_counts["OSINT"] + provenance_counts["SANDBOX"]
    capture_dir = Path(report_file).parent / "responses"
    b_capture_dir = Path(report_file).parent / "responses_control_b"

    b_audits = read_final_audits(b_capture_dir) if control_b else []
    c_audits = read_final_audits(capture_dir)
    gate_decision = report.get("gate_decision")
    is_complex = gate_decision == "complex"
    audit_valid, audit_problems, no_new_external = (True, [], False)
    if is_complex and control_b is not None:
        audit_valid, audit_problems, no_new_external = validate_control_audits(
            b_audits, c_audits, bundle_external
        )
    internal_digest = None
    if internal is not None:
        internal_digest = hashlib.sha256(
            canonical_bytes(internal.model_dump(mode="json"))
        ).hexdigest()
    rejects, proposals_total, proposals_invalid = count_final_rejects(capture_dir)
    accepted = final_state.get("final_validated")
    proposals_total += count_candidate_proposals(
        accepted.model_dump() if accepted is not None else None
    )
    refusals = count_attempt_refusals([capture_dir, b_capture_dir])
    rag_cases: list[dict[str, Any]] = []
    enrichment = final_state.get("enrichment")
    for case in getattr(enrichment, "rag", None) or []:
        rag_cases.append(
            {
                "case_id": str(getattr(case, "case_id", "")),
                "family_group": str(getattr(case, "family_group", "")),
                "distance": getattr(case, "distance", None),
                "embedding_model_id": str(getattr(case, "embedding_model_id", "")),
            }
        )

    row_out: dict[str, Any] = {
        "sample_id": row["sample_id"],
        "split": split,
        "variant": variant,
        "measurement_scope": measurement_scope,
        "source_dataset": row["source_dataset"],
        "family_group": row["family_group"],
        "raw_path": row["raw_path"],
        "raw_sha256": row["raw_sha256"],
        "input_format": row["input_format"],
        "public_source": bool(row["public_source"]),
        "label": row["normalized_label"],
        "run_id": report["run_id"],
        "report_dir": str(report_dir_rel),
        "report_path": str(report_rel),
        "report_sha256": _file_sha256(report_file),
        "started_at": (report.get("reproducibility") or {}).get("started_at"),
        "runtime_config_sha256": (report.get("reproducibility") or {}).get("config_sha256"),
        "gate_decision": gate_decision,
        "gate_reasons": report.get("gate_reasons"),
        "final_source": report.get("final_source"),
        "run_status": report.get("run_status"),
        "predicted": report.get("final_verdict"),
        "predicted_valid": report.get("final_verdict") is not None,
        "final_confidence": report.get("final_confidence"),
        "final_probabilities": report.get("final_probabilities"),
        "internal_verdict": report.get("internal_verdict"),
        "internal_confidence": report.get("internal_confidence"),
        "verdict_changed": report.get("verdict_changed"),
        "recommended_action": report.get("recommended_action"),
        "policy_reasons": report.get("policy_reasons"),
        "timings": report.get("timings"),
        "llm_calls": report.get("llm_calls"),
        "control_b": control_b,
        "internal_assessment_sha256": internal_digest,
        "untrusted_email_sha256_b": (b_audits[-1].get("untrusted_email_sha256") if b_audits else None),
        "untrusted_email_sha256_c": (c_audits[-1].get("untrusted_email_sha256") if c_audits else None),
        "tool_status_digest_b": (b_audits[-1].get("tool_status_digest") if b_audits else None),
        "tool_status_digest_c": (c_audits[-1].get("tool_status_digest") if c_audits else None),
        "evidence_provenance_counts": provenance_counts,
        "bundle_external_evidence": bundle_external,
        "rag_cases": rag_cases,
        "extras": {
            "rejected_final_candidates": rejects,
            "proposals_total": proposals_total,
            "proposals_invalid": proposals_invalid,
            "refusals": refusals,
        },
        "abc_audit": {
            "applicable": bool(is_complex and control_b is not None),
            "valid": audit_valid,
            "problems": audit_problems,
            "no_new_external_evidence": no_new_external,
            "b_attempt_audits": b_audits,
            "c_attempt_audits": c_audits,
        },
        "notes": [],
    }
    if parsed is not None and str(parsed.email_sha256) != str(row["raw_sha256"]):
        # Defensive: the runner raises before this can happen, but the row
        # records any discrepancy loudly instead of hiding it.
        row_out["notes"].append("parsed_email_sha256_mismatch_recorded")
    if parsed is None:
        row_out["notes"].append("parse_failed_technical_failure_stays_in_denominator")
    return row_out


def controls_from_rows(rows: list[Mapping[str, Any]]) -> list[Mapping[str, Any] | None]:
    """A/B/C payloads expected by ``src.metrics.abc_block`` (rows order).

    A COMPLEX sample whose nominal run never reached the FINAL phase
    (parse failure) cannot carry a B control: it is marked
    ``excluded_technical`` (a truthful technical exclusion from the paired
    comparison, still counted in the global denominators). A COMPLEX sample
    that DID reach the FINAL phase without a control payload is a runner
    bug and marks the audit invalid.
    """

    controls: list[Mapping[str, Any] | None] = []
    for row in rows:
        control_b = row.get("control_b")
        gate_decision = row.get("gate_decision")
        if gate_decision != "complex":
            controls.append(None)
            continue
        parse_failed = "parse_failed_technical_failure_stays_in_denominator" in (
            row.get("notes") or []
        )
        attempted = bool(isinstance(control_b, Mapping) and control_b.get("attempted"))
        if parse_failed or (isinstance(control_b, Mapping) and not attempted):
            # The nominal run never reached the FINAL phase: no B control is
            # possible. This is a technical exclusion from the paired
            # comparison (still counted in the global denominators), not an
            # audit violation.
            controls.append(
                {
                    "excluded_technical": True,
                    "a": {"verdict": row.get("internal_verdict"), "confidence": row.get("internal_confidence")},
                    "b": {"verdict": None, "confidence": None},
                    "c": {"verdict": row.get("predicted"), "confidence": row.get("final_confidence")},
                    "audit": {"valid": True, "problems": [], "bundle_external_evidence": 0},
                    "b_cost_usd": None,
                    "b_latency_ms": None,
                }
            )
            continue
        audit_info = row.get("abc_audit") or {}
        if not isinstance(control_b, Mapping):
            controls.append(
                {
                    "excluded_technical": False,
                    "a": {"verdict": None, "confidence": None},
                    "b": {"verdict": None, "confidence": None},
                    "c": {"verdict": None, "confidence": None},
                    "audit": {
                        "valid": False,
                        "problems": [
                            "missing A/B/C control payload for a COMPLEX "
                            "sample that reached the FINAL phase"
                        ],
                        "bundle_external_evidence": 0,
                    },
                    "b_cost_usd": None,
                    "b_latency_ms": None,
                }
            )
            continue
        controls.append(
            {
                "excluded_technical": False,
                "a": {
                    "verdict": row.get("internal_verdict"),
                    "confidence": row.get("internal_confidence"),
                },
                "b": {
                    "verdict": control_b.get("verdict"),
                    "confidence": control_b.get("confidence"),
                },
                "c": {
                    "verdict": row.get("predicted"),
                    "confidence": row.get("final_confidence"),
                },
                "audit": {
                    "valid": bool(audit_info.get("valid")),
                    "problems": list(audit_info.get("problems") or []),
                    "no_new_external_evidence": bool(
                        audit_info.get("no_new_external_evidence")
                    ),
                    "bundle_external_evidence": int(
                        row.get("bundle_external_evidence", 0) or 0
                    ),
                },
                "b_cost_usd": control_b.get("cost_usd"),
                "b_latency_ms": control_b.get("latency_ms"),
            }
        )
    return controls


def extras_from_rows(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row.get("extras") or {}) for row in rows]


# ---------------------------------------------------------------------------
# Paired baseline artifact (docs/evaluation.md §8.7, TICKET-15)
# ---------------------------------------------------------------------------


def _row_prediction(row: Mapping[str, Any]) -> str | None:
    """Typed delivered prediction of one archived evaluation row."""

    value = row.get("predicted")
    return value if isinstance(value, str) and value in LABELS else None


def build_paired_baseline_payload(
    paired: PairedBaseline,
    run_rows: list[Mapping[str, Any]],
    rows: list[Mapping[str, Any]],
    ablation: RagAblation,
) -> dict[str, Any]:
    """Full paired artifact: identity, denominators, comparison, RAG usage.

    Built only after BOTH series were validated. A missing/extra/duplicated
    sample_id or a denominator mismatch raises ``PairedRunError``: no delta
    is published from two series that are not exactly the same samples. The
    comparison reuses the §8.3 paired engine through
    ``src.metrics.paired_variant_block`` and stays diagnostic
    (``performance_claims_allowed=false``, INCONCLUSIVE valid).
    """

    gold_by_id = {str(row["sample_id"]): row for row in run_rows}
    expected_ids = sorted(gold_by_id)
    current_by_id = {str(row["sample_id"]): row for row in rows}
    if len(current_by_id) != len(rows):
        raise PairedRunError("current run contains duplicated sample_id rows")
    paired_by_id = paired.by_sample_id
    if len(paired_by_id) != len(paired.rows):
        raise PairedRunError("paired run contains duplicated sample_id rows")
    for name, present in (
        ("current", sorted(current_by_id)),
        ("paired", sorted(paired_by_id)),
    ):
        if present != expected_ids:
            raise PairedRunError(
                f"{name} run does not reproduce the deterministic selection "
                f"(missing={sorted(set(expected_ids) - set(present))}, "
                f"extra={sorted(set(present) - set(expected_ids))})"
            )
    if len(rows) != len(paired.rows) or len(rows) != len(expected_ids):
        raise PairedRunError(
            "denominators differ: "
            f"current={len(rows)}, paired={len(paired.rows)}, "
            f"selection={len(expected_ids)}"
        )

    labels = [str(gold_by_id[sample_id]["normalized_label"]) for sample_id in expected_ids]
    baseline_predictions = [
        _row_prediction(paired_by_id[sample_id]) for sample_id in expected_ids
    ]
    rag_predictions = [
        _row_prediction(current_by_id[sample_id]) for sample_id in expected_ids
    ]
    comparison = paired_variant_block(
        labels,
        baseline_predictions,
        rag_predictions,
        baseline_variant=BASELINE_VARIANT,
        variant=RAG_VARIANT,
    )
    usage_rows = [
        list(current_by_id[sample_id].get("rag_cases") or []) for sample_id in expected_ids
    ]
    per_sample: list[dict[str, Any]] = []
    for index, sample_id in enumerate(expected_ids):
        baseline_row = paired_by_id[sample_id]
        current_row = current_by_id[sample_id]
        per_sample.append(
            {
                "sample_id": sample_id,
                "label": gold_by_id[sample_id]["normalized_label"],
                "baseline_predicted": baseline_row.get("predicted"),
                "rag_predicted": current_row.get("predicted"),
                "prediction_changed": (
                    baseline_row.get("predicted") != current_row.get("predicted")
                ),
                "baseline_gate_decision": baseline_row.get("gate_decision"),
                "rag_gate_decision": current_row.get("gate_decision"),
                "rag_cases": usage_rows[index],
            }
        )
    return {
        "schema_version": "paired-baseline-1.0",
        "variant": RAG_VARIANT,
        "paired_variant": BASELINE_VARIANT,
        "paired_with": _project_relative(paired.run_dir),
        "paired_manifest_sha256": paired.manifest_sha256,
        "paired_predictions_sha256": paired.predictions_sha256,
        "measurement_scope": paired.manifest.get("measurement_scope"),
        "performance_claims_allowed": False,
        "selection_identity": {
            "verified": True,
            "sample_selection_rule": SAMPLE_SELECTION_RULE,
            "sample_ids": expected_ids,
        },
        "denominators": {
            "current_run": len(rows),
            "paired_run": len(paired.rows),
            "selection": len(expected_ids),
            "identical": True,
        },
        "comparison": comparison,
        "per_sample": per_sample,
        "rag_usage": {
            "sample_count": len(expected_ids),
            "samples_with_neighbour": sum(1 for cases in usage_rows if cases),
            "samples_without_neighbour": sum(1 for cases in usage_rows if not cases),
            "total_neighbours": sum(len(cases) for cases in usage_rows),
            "per_sample": [
                {
                    "sample_id": sample_id,
                    "n_cases": len(usage_rows[index]),
                    "case_ids": [
                        str(case.get("case_id")) for case in usage_rows[index]
                    ],
                    "distances": [
                        case.get("distance") for case in usage_rows[index]
                    ],
                }
                for index, sample_id in enumerate(expected_ids)
            ],
        },
        "rag_index": ablation.description,
        "baseline_run_read_only": True,
        "note": (
            "paired diagnostic ablation of the bounded smoke (docs/evaluation.md "
            "§8.7): never a performance claim (performance_claims_allowed=false), "
            "INCONCLUSIVE is a valid outcome, feeds T19C; the first full "
            "benchmark including RAG is TICKET-19E"
        ),
    }


def build_rag_ablation_block(
    ablation: RagAblation, paired: PairedBaseline
) -> dict[str, Any]:
    """Manifest block describing how the RAG ablation was enabled and paired."""

    return {
        "capability": {
            "tools_rag_enabled_effective": True,
            "rag_enabled_effective": True,
            "in_memory_overrides": [
                "tools.rag.enabled=true",
                "RAG_ENABLED=true",
            ],
            "frozen_tools_yaml_unchanged": True,
            "note": (
                "the frozen configs/tools.yaml keeps rag.enabled=false (the G6 "
                "baseline file is never rewritten); the paired ablation applies "
                "the capability in memory for this run only"
            ),
        },
        "index": ablation.description,
        "paired_with": _project_relative(paired.run_dir),
        "paired_baseline_artifact": "paired_baseline.json",
        "policy": (
            "diagnostic smoke only (performance_claims_allowed=false); "
            "INCONCLUSIVE is a valid outcome; results feed T19C; the first "
            "full benchmark including RAG is TICKET-19E"
        ),
    }


# ---------------------------------------------------------------------------
# Artifact writers
# ---------------------------------------------------------------------------


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    temporary.replace(path)


def write_predictions_atomic(path: Path, rows: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        for row in rows
    )
    temporary = path.with_suffix(".jsonl.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def write_matrix_csv(path: Path, metrics: Mapping[str, Any]) -> None:
    """6x6 confusion matrix + explicit abstention column (§8.2)."""

    delivered = metrics["delivered"]
    matrix = delivered["confusion"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["true\\predicted", *matrix["labels"], "abstention(null)"]
        )
        for index, label in enumerate(matrix["labels"]):
            writer.writerow(
                [label, *matrix["with_abstention_column"][index]]
            )
        writer.writerow(
            ["abstentions_by_true_class", *matrix["abstention_by_true_class"].values()]
        )


def _label_support(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Label support over the given rows in fixed taxonomy order."""

    return {
        label: sum(1 for row in rows if str(row["normalized_label"]) == label)
        for label in LABELS
    }


def build_manifest(
    *,
    settings: Settings,
    evaluation_config: EvaluationConfig,
    evaluation_config_path: Path,
    experiment_lock_path: Path,
    gold_path: Path,
    gold_rows: list[Mapping[str, Any]],
    out_dir: Path,
    variant: str,
    split: str,
    rows: list[Mapping[str, Any]],
    started_at: str,
    mode: str,
    measurement_scope: str,
    performance_claims_allowed: bool,
    sample_selection_rule: str,
    selected_ids: list[str],
    full_support: dict[str, int],
    rag_ablation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run manifest: identity, frozen inputs, pricing, tool/config status.

    ``rag_ablation`` (TICKET-15, §8.7) describes the in-memory RAG
    capability override, the frozen index identity and the read-only paired
    baseline; it is absent for the frozen baseline variant.
    """

    commit = None
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        commit = None
    tool_status = {
        "virustotal": {
            "key_present": settings.secret_presence()["VT_API_KEY"],
            "access_authorized": bool(settings.VT_ACCESS_AUTHORIZED),
        },
        "opencti": {
            "key_present": settings.secret_presence()["OPENCTI_API_KEY"],
            "url": settings.OPENCTI_URL,
        },
        "urlscan": {
            "key_present": settings.secret_presence()["URLSCAN_API_KEY"],
        },
        "egress_allow_real_urls": _egress_allow_real_urls(settings),
        "egress_approved_services": _egress_approved_services(settings),
        "vision_enabled": bool(settings.MODEL_SUPPORTS_VISION),
        "rag_enabled": bool(settings.RAG_ENABLED),
        "qr_decode_enabled": bool(settings.QR_DECODE_ENABLED),
    }
    manifest: dict[str, Any] = {
        "schema_version": "eval-manifest-1.0",
        "mode": mode,
        "run_id": out_dir.name,
        "date_time_utc": started_at,
        "git_commit": commit,
        "variant": variant,
        "split": split,
        "sample_count": len(rows),
        "measurement_scope": measurement_scope,
        "performance_claims_allowed": performance_claims_allowed,
        "sample_selection_rule": sample_selection_rule,
        "selected_sample_ids": selected_ids,
        "full_dev_label_support": full_support,
        "model": settings.LITELLM_MODEL,
        "provider": evaluation_config.pricing_snapshot.get("provider"),
        "chat_url": settings.LITELLM_CHAT_URL,
        "reasoning_configuration": {
            "internal": "medium",
            "final": "xhigh",
            "control_b": "xhigh",
        },
        "prompt_versions": {
            "prompts_version": "V1 (frozen)",
            "internal_sha256": _file_sha256(PROJECT_ROOT / "prompts" / "internal_assessment.txt"),
            "final_sha256": _file_sha256(PROJECT_ROOT / "prompts" / "final_assessment.txt"),
        },
        "gate_configuration": {
            "file": "configs/gate.yaml",
            "sha256": _file_sha256(PROJECT_ROOT / "configs" / "gate.yaml"),
            "values": _gate_values(settings),
        },
        "policy_configuration": {
            "sha256": _file_sha256(PROJECT_ROOT / "configs" / "policy.yaml"),
            "values": _policy_values(settings),
        },
        "tools_configuration": {
            "sha256": _file_sha256(PROJECT_ROOT / "configs" / "tools.yaml"),
        },
        "evaluation_config": {
            "path": str(evaluation_config_path.relative_to(PROJECT_ROOT)),
            "sha256": _file_sha256(evaluation_config_path),
        },
        "experiment_lock": {
            "path": str(experiment_lock_path.relative_to(PROJECT_ROOT)),
            "sha256": _file_sha256(experiment_lock_path),
        },
        "gold_partition": {
            "split": split,
            "path": str(gold_path.relative_to(PROJECT_ROOT)),
            "sha256": _file_sha256(gold_path),
            "record_count": len(gold_rows),
            "family_count": len({str(row["family_group"]) for row in gold_rows}),
        },
        "retry_policy": {
            "max_llm_attempts": settings.MAX_LLM_ATTEMPTS,
            "max_email_seconds": settings.MAX_EMAIL_SECONDS,
            "internal_phase_seconds": settings.INTERNAL_PHASE_SECONDS,
            "final_phase_seconds": settings.FINAL_PHASE_SECONDS,
            "internal_max_output_tokens": settings.INTERNAL_MAX_OUTPUT_TOKENS,
            "final_max_output_tokens": settings.FINAL_MAX_OUTPUT_TOKENS,
        },
        "pricing_snapshot": dict(evaluation_config.pricing_snapshot),
        "tool_status": tool_status,
        "runtime_config_sha256": rows[0].get("runtime_config_sha256") if rows else None,
        "completed_at_utc": datetime.now(UTC).isoformat(),
        "secrets_included": False,
    }
    if rag_ablation is not None:
        manifest["rag_ablation"] = dict(rag_ablation)
    return manifest


def _egress_allow_real_urls(settings: Settings) -> bool:
    tools = load_yaml_config(Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig)
    return bool(tools.egress.allow_real_urls)


def _egress_approved_services(settings: Settings) -> list[str]:
    tools = load_yaml_config(Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig)
    return list(tools.egress.approved_services)


def _gate_values(settings: Settings) -> dict[str, Any]:
    gate = load_yaml_config(Path(settings.CONFIG_DIR) / "gate.yaml", GateConfig)
    return {
        "version": gate.version,
        "min_confidence": gate.min_confidence,
        "min_margin": gate.min_margin,
        "enrich_http_urls": gate.enrich_http_urls,
        "enrich_non_inline_attachments": gate.enrich_non_inline_attachments,
        "enrich_on_material_coverage_gap": gate.enrich_on_material_coverage_gap,
        "rule_order": "R1,R2,R3 (BASELINE V0)",
    }


def _policy_values(settings: Settings) -> dict[str, Any]:
    policy = load_yaml_config(Path(settings.CONFIG_DIR) / "policy.yaml", PolicyConfig)
    return {
        "version": policy.version,
        "auto_min_confidence": policy.auto_min_confidence,
        "auto_min_margin": policy.auto_min_margin,
        "escalate_malicious_min_confidence": policy.escalate_malicious_min_confidence,
        "auto_labels": list(policy.auto_labels),
        "blocked_reason_codes": dict(policy.blocked_reason_codes),
    }


def write_human_report(path: Path, metrics: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    """Deterministic human-readable summary of the metrics (no email content)."""

    def _fmt(value: Any, digits: int = 4) -> str:
        if value is None:
            return "n/a"
        if isinstance(value, float):
            return f"{value:.{digits}f}"
        return str(value)

    lines: list[str] = []
    delivered = metrics["delivered"]
    scope = manifest.get("measurement_scope", "full_dev_baseline")
    claims_allowed = bool(manifest.get("performance_claims_allowed", True))
    lines.append(
        f"# Dev baseline evaluation ({manifest['variant']}, split={manifest['split']})"
    )
    lines.append("")
    if not claims_allowed:
        lines.append(
            "> **DIAGNOSTIC HARNESS SMOKE — NOT a performance baseline.** "
            "measurement_scope=smoke, performance_claims_allowed=false. The "
            "records below validate plumbing only (one lexicographically "
            "first sample per dev label with support>0); supports, Macro-F1 "
            "and every rate here are NOT representative and no statistical "
            "validation is claimed. The first full-corpus benchmark is "
            "TICKET-19E."
        )
        lines.append("")
    lines.append(f"- measurement_scope: {scope}")
    lines.append(f"- sample_selection_rule: {manifest.get('sample_selection_rule')}")
    lines.append(f"- selected_sample_ids: {manifest.get('selected_sample_ids')}")
    lines.append(f"- full_dev_label_support: {manifest.get('full_dev_label_support')}")
    lines.append(f"- run id: {manifest.get('run_id')}")
    lines.append(f"- date (UTC): {manifest.get('date_time_utc')}")
    lines.append(f"- git commit: {manifest.get('git_commit')}")
    lines.append(f"- model: {manifest.get('model')} via {manifest.get('provider')}")
    reasoning_config = manifest.get("reasoning_configuration") or {}
    lines.append(
        f"- reasoning: internal={reasoning_config.get('internal')}, "
        f"final={reasoning_config.get('final')}"
    )
    lines.append(
        f"- samples: {metrics['n_total']} (valid predictions "
        f"{metrics['n_valid_predictions']}, abstentions {metrics['n_abstentions']})"
    )
    gate_values = (manifest.get("gate_configuration") or {}).get("values") or {}
    lines.append(
        f"- gate BASELINE V0: {gate_values.get('min_confidence')}/"
        f"{gate_values.get('min_margin')} (R1–R3)"
    )
    lines.append("")
    lines.append("## Label support (fixed order)")
    lines.append("")
    lines.append("| class | support | predicted | precision | recall | F1 |")
    lines.append("|---|---|---|---|---|---|")
    for label in metrics["labels"]:
        stats = delivered["per_class"][label]
        lines.append(
            f"| {label} | {stats['support']} | {stats['predicted']} "
            f"| {_fmt_opt(stats['precision'])} | {_fmt_opt(stats['recall'])} "
            f"| {_fmt_opt(stats['f1'])} |"
        )
    lines.append("")
    lines.append(
        f"- Macro-F1 (supported classes): {_fmt_opt(delivered['macro_f1']['value'])} "
        f"({delivered['macro_f1']['status']})"
    )
    lines.append(
        f"- Six-class Macro-F1: {_fmt_opt(delivered['macro_f1_six_class']['value'])} "
        f"({delivered['macro_f1_six_class']['status']})"
    )
    fpr = metrics["fpr"]
    lines.append(
        f"- FPR legitime: strict={_fmt_opt(fpr['strict_legitime_fpr'])}, "
        f"malicious={_fmt_opt(fpr['malicious_legitime_fpr'])}, "
        f"abstention={_fmt_opt(fpr['legitime_abstention_rate'])} (support {fpr['legitime_support']})"
    )
    lines.append("")
    lines.append("## SIMPLE / COMPLEX paths (BASELINE V0 gate)")
    for name in ("simple", "complex"):
        path_block = metrics["paths"][name]
        lines.append(
            f"- {name}: n={path_block['n']} ({_fmt_pct(path_block['pct'])}), "
            f"macro-F1(supported)={_fmt_opt(path_block['quality']['macro_f1']['value'])}, "
            f"mean cost={_fmt_opt(path_block['cost']['mean_usd'], 6)} USD, "
            f"mean latency={_fmt_opt(path_block['latency']['mean_ms'], 1)} ms"
        )
    lines.append("")
    lines.append("## INTERNAL (A) -> FINAL (C) on the same run (§8.3)")
    for scope in ("all", "complex_only"):
        block = metrics["internal_to_final"][scope]
        lines.append(
            f"- {scope}: n={block['n_comparable']}, changed={block['n_changed_verdict']}, "
            f"wrong→right={block['buckets']['wrong_to_right']}, "
            f"right→wrong={block['buckets']['right_to_wrong']}, "
            f"wrong→wrong={block['buckets']['wrong_to_wrong']}, "
            f"right→right={block['buckets']['right_to_right']}, "
            f"Δmacro-F1={_fmt_opt(block['delta_macro_f1'])}"
        )
    abc = metrics.get("abc")
    if abc:
        audit = abc["audit"]
        lines.append("")
        lines.append("## A/B/C control (COMPLEX dev samples)")
        lines.append(f"- complex n={abc['complex_n']}, audit valid={audit['valid']}")
        if audit["problems"]:
            for problem in audit["problems"]:
                lines.append(f"  - audit problem: {problem}")
        for name in ("A_to_B", "B_to_C"):
            block = abc[name]
            lines.append(
                f"- {name}: n={block['n_comparable']}, changed={block['n_changed_verdict']}, "
                f"wrong→right={block['buckets']['wrong_to_right']}, "
                f"right→wrong={block['buckets']['right_to_wrong']}, "
                f"wrong→wrong={block['buckets']['wrong_to_wrong']}, "
                f"right→right={block['buckets']['right_to_right']}, "
                f"Δmacro-F1={_fmt_opt(block['delta_macro_f1'])}"
            )
        lines.append(
            f"- external bundle: {audit['samples_with_external_evidence_bundle']} sample(s) "
            f"with admissible external evidence, "
            f"{audit['samples_no_new_external_evidence']} with no_new_external_evidence"
        )
    cost = metrics["cost"]
    lines.append("")
    lines.append(
        f"## Cost (variable inference; {cost['pricing_snapshot'].get('currency')}) "
        f"status={cost['status']}"
    )
    lines.append(
        f"- total={_fmt_opt(cost['total_usd'], 6)} USD, mean per email="
        f"{_fmt_opt(cost['mean_usd'], 6)} USD, provider-reported="
        f"{_fmt_opt(cost['provider_reported_total_usd'], 6)} "
        f"({cost['provider_status']}), unknown calls={cost['unknown_call_count']}"
    )
    latency = metrics["latency"]
    lines.append(
        f"## Latency: mean={_fmt_opt(latency['overall']['mean_ms'], 1)} ms, "
        f"median={_fmt_opt(latency['overall']['median_ms'], 1)} ms, "
        f"p95={_fmt_opt(latency['overall']['p95_ms'], 1)} ms, "
        f"max={_fmt_opt(latency['overall']['max_ms'], 1)} ms, "
        f"total={_fmt_opt(latency['overall']['total_ms'], 1)} ms"
    )
    schema_block = metrics["schema"]
    lines.append(
        f"## Schema validity: first attempt internal="
        f"{schema_block['first_attempt_valid']['internal']['valid']}/"
        f"{schema_block['first_attempt_valid']['internal']['known']}, final="
        f"{schema_block['first_attempt_valid']['final']['valid']}/"
        f"{schema_block['first_attempt_valid']['final']['known']}; "
        f"after retry internal={schema_block['valid_after_retry']['internal']}, "
        f"final={schema_block['valid_after_retry']['final']}; retries="
        f"{schema_block['retries']}; refusals={schema_block['refusals']}"
    )
    lines.append("")
    lines.append("## External tool coverage (statuses preserved with their cause)")
    for tool, stats in metrics["tool_coverage"]["tools"].items():
        lines.append(
            f"- {tool}: candidates={stats['candidates']}, statuses={stats['statuses']}, "
            f"reasons={stats['reasons']}, requests_sent={stats['requests_sent']}"
        )
    lines.append("")
    lines.append("## Policy coverage")
    for action in ("AUTO", "REVIEW", "ESCALATE"):
        entry = metrics["policy"]["coverage"][action]
        lines.append(f"- {action}: {entry['count']} ({_fmt_pct(entry['pct'])})")
    lines.append(
        f"- malicious AUTO={metrics['policy']['malicious_auto_count']}, "
        f"legitime ESCALATE={metrics['policy']['legitime_escalate_count']}, "
        f"benign AUTO precision={_fmt_opt(metrics['policy']['benign_auto']['precision'])} "
        f"(support {metrics['policy']['benign_auto']['support']})"
    )
    paired = manifest.get("paired_baseline")
    if paired:
        comparison = paired.get("comparison") or {}
        buckets = comparison.get("buckets") or {}
        usage = paired.get("rag_usage") or {}
        lines.append("")
        lines.append("## Paired baseline → RAG (diagnostic smoke, §8.7)")
        lines.append(f"- paired_with: {paired.get('paired_with')} (read-only)")
        lines.append(
            f"- paired n={comparison.get('n_comparable')}, "
            f"changed={comparison.get('n_changed_verdict')}, "
            f"wrong→right={buckets.get('wrong_to_right')}, "
            f"right→wrong={buckets.get('right_to_wrong')}, "
            f"Δmacro-F1={_fmt_opt(comparison.get('delta_macro_f1'))}"
        )
        lines.append(
            f"- RAG context: {usage.get('samples_with_neighbour')}/"
            f"{usage.get('sample_count')} samples received at least one public "
            f"neighbour, total={usage.get('total_neighbours')}"
        )
        lines.append(
            "- diagnostic only (performance_claims_allowed=false); INCONCLUSIVE "
            "valid; feeds T19C; the first full benchmark including RAG is TICKET-19E"
        )
    lines.append("")
    lines.append("## Limitations")
    for limitation in metrics["limitations"]:
        lines.append(f"- {limitation}")
    for limitation in manifest.get("published_limitations_extra", []) or []:
        lines.append(f"- {limitation}")
    lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fmt_opt(value: Any, digits: int = 4) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.{digits}f}"


def _fmt_pct(value: Any) -> str:
    if value is None:
        return "n/a"
    return f"{float(value) * 100:.1f}%"


# ---------------------------------------------------------------------------
# LIVE dev baseline (variant baseline)
# ---------------------------------------------------------------------------


def check_runtime_ready(settings: Settings, lock: Mapping[str, Any]) -> list[str]:
    """Official runtime binding checks (no secret value is ever touched)."""

    problems: list[str] = []
    runtime = lock.get("runtime") or {}
    if settings.LITELLM_API_KEY is None:
        problems.append(
            "LITELLM_API_KEY absent: the official LLM endpoint cannot be "
            "called and no response may be simulated (BLOCKED, not FAIL)"
        )
    if settings.LITELLM_MODEL != runtime.get("model"):
        problems.append(
            f"model binding mismatch: settings {settings.LITELLM_MODEL!r} vs "
            f"lock {runtime.get('model')!r}"
        )
    return problems


def run_live(
    args: argparse.Namespace,
    evaluation_config: EvaluationConfig,
    lock: Mapping[str, Any],
) -> int:
    """Execute the real dev baseline and archive every artifact."""

    split = args.split
    variant = args.variant
    if variant not in (BASELINE_VARIANT, RAG_VARIANT):
        print(
            f"FAIL: unknown variant {variant!r} (supported: "
            f"{BASELINE_VARIANT!r}, {RAG_VARIANT!r})",
            file=sys.stderr,
        )
        return EXIT_FAIL
    paired_with = args.paired_with
    if variant == RAG_VARIANT and not paired_with:
        print(
            f"FAIL: --variant {RAG_VARIANT} requires --paired-with "
            "<archived baseline run dir> (docs/evaluation.md §8.7): the "
            "baseline is read only, never replayed",
            file=sys.stderr,
        )
        return EXIT_FAIL
    if variant != RAG_VARIANT and paired_with:
        print(
            f"FAIL: --paired-with is only valid with --variant {RAG_VARIANT}",
            file=sys.stderr,
        )
        return EXIT_FAIL
    if split == FORBIDDEN_SPLIT:
        print(
            "BLOCKED: gold_test.jsonl is not readable by the TICKET-14 dev "
            "workflow; the terminal test evaluation belongs to the later "
            "authorized ticket",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    if split != "dev":
        print(f"FAIL: unsupported split {split!r}", file=sys.stderr)
        return EXIT_FAIL

    sample_profile = args.sample_profile
    if sample_profile not in (SMOKE_PROFILE, FULL_PROFILE):
        print(f"FAIL: unknown sample profile {sample_profile!r}", file=sys.stderr)
        return EXIT_FAIL
    measurement_scope = "smoke" if sample_profile == SMOKE_PROFILE else "full_dev_baseline"
    performance_claims_allowed = sample_profile == FULL_PROFILE

    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    if out_dir.exists() and any(out_dir.iterdir()):
        print(
            f"FAIL: --out directory is not empty: {out_dir} (never overwrite "
            "an existing run silently)",
            file=sys.stderr,
        )
        return EXIT_FAIL

    lock_problems = verify_experiment_lock(lock)
    if lock_problems:
        for problem in lock_problems:
            print(f"FAIL (experiment lock): {problem}", file=sys.stderr)
        return EXIT_FAIL

    settings = load_settings()
    settings = settings.model_copy(
        update={
            "RUNS_DIR": out_dir.resolve(),
            "CONFIG_DIR": (PROJECT_ROOT / "configs").resolve(),
        }
    )
    runtime_problems = check_runtime_ready(settings, lock)
    if runtime_problems:
        for problem in runtime_problems:
            print(f"BLOCKED: {problem}", file=sys.stderr)
        return EXIT_BLOCKED

    # --- paired baseline (READ ONLY) BEFORE any call -------------------------
    paired: PairedBaseline | None = None
    if variant == RAG_VARIANT:
        paired_dir = Path(paired_with)
        if not paired_dir.is_absolute():
            paired_dir = PROJECT_ROOT / paired_dir
        try:
            paired = load_paired_baseline(paired_dir, expected_scope=measurement_scope)
        except PairedRunError as error:
            print(f"FAIL: {error}", file=sys.stderr)
            return EXIT_FAIL

    # --- gold validation BEFORE any call -------------------------------------
    # The FULL partition integrity is always validated (all 83 records),
    # whatever the live measurement scope is.
    gold_rows, gold_path = load_gold_records(evaluation_config, split)
    verified_bytes, raw_failures = validate_gold_raw_files(gold_rows)
    if raw_failures:
        for failure in raw_failures:
            print(f"FAIL (gold validation): {failure}", file=sys.stderr)
        return EXIT_FAIL

    full_support = _label_support(gold_rows)
    if sample_profile == SMOKE_PROFILE:
        run_rows = select_smoke_sample(gold_rows)
    else:
        run_rows = gold_rows
    selected_ids = [str(row["sample_id"]) for row in run_rows]
    if paired is not None:
        # Exact sample-id identity + label/hash identity (§8.7): a missing or
        # extra sample makes the paired delta meaningless.
        try:
            verify_paired_selection(paired, run_rows)
        except PairedRunError as error:
            print(f"FAIL: {error}", file=sys.stderr)
            return EXIT_FAIL

    # --- RAG ablation preparation BEFORE any provider call -------------------
    tools_override: ToolsConfig | None = None
    rag_adapter: RagAdapter | None = None
    rag_ablation: RagAblation | None = None
    if variant == RAG_VARIANT:
        tools_config = load_yaml_config(
            Path(settings.CONFIG_DIR) / "tools.yaml", ToolsConfig
        )
        try:
            rag_ablation = prepare_rag_ablation(settings, tools_config)
        except RagUnavailableError as error:
            print(f"BLOCKED: {error}", file=sys.stderr)
            return EXIT_BLOCKED
        except RagError as error:
            print(f"FAIL: {error}", file=sys.stderr)
            return EXIT_FAIL
        settings = rag_ablation.effective_settings
        tools_override = rag_ablation.effective_tools
        rag_adapter = rag_ablation.adapter
        description = rag_ablation.description
        print(
            f"[rag] paired ablation: index={description['index_dir']} "
            f"count={description['count']} "
            f"model={description['embedding_model_id']} "
            f"paired_with={_project_relative(paired.run_dir)}"
        )

    pricing = evaluation_config.pricing_snapshot
    if sample_profile == SMOKE_PROFILE:
        print(
            f"[smoke] measurement_scope=smoke: {len(selected_ids)} live "
            "records, diagnostic only (performance_claims_allowed=false); "
            "full Gold metadata/raw integrity validated for all "
            f"{len(gold_rows)} records"
        )
    started_at = datetime.now(UTC).isoformat()
    rows: list[dict[str, Any]] = []
    consecutive_infra_failures = 0
    any_internal_ok = False
    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="eml_eval_")
    except OSError as error:  # pragma: no cover - environment failure
        print(f"FAIL: cannot create a temporary directory: {error}", file=sys.stderr)
        return EXIT_FAIL
    try:
        for index, gold_row in enumerate(run_rows):
            sample_id = str(gold_row["sample_id"])
            safe_name = "".join(
                character if character.isalnum() or character in "._-" else "_"
                for character in sample_id
            )
            profile = derive_source_profile(gold_row, evaluation_config)
            email_file = Path(temp_dir.name) / f"{index:04d}_{safe_name}.eml"
            email_file.write_bytes(verified_bytes[sample_id])
            rag_identity_kwargs: dict[str, Any] = {}
            if variant == RAG_VARIANT:
                current_family_group = str(gold_row.get("family_group") or "").strip() or None
                current_duplicate_group = str(gold_row.get("duplicate_group") or "").strip() or None
                current_campaign_id = str(gold_row.get("campaign_id") or "").strip() or None
                rag_exclusions = {
                    value
                    for value in (
                        current_family_group,
                        current_duplicate_group,
                        current_campaign_id,
                    )
                    if value is not None
                }
                rag_identity_kwargs = {
                    "rag_exclusions": rag_exclusions,
                    "current_duplicate_group": current_duplicate_group,
                    "current_family_group": current_family_group,
                    "current_campaign_id": current_campaign_id,
                }
            try:
                report, final_state = run_nominal_pipeline(
                    settings,
                    email_file,
                    profile,
                    tools_override=tools_override,
                    rag_adapter=rag_adapter,
                    **rag_identity_kwargs,
                )
            except Exception as error:
                # A pipeline exception is an implementation/infrastructure
                # failure, not a provider outcome: abort loudly instead of
                # claiming a measurement row without an archived report.
                print(
                    f"FAIL: sample {sample_id}: pipeline exception: "
                    f"{type(error).__name__}: {error}",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            report_path_value = final_state.get("report_path")
            if not isinstance(report_path_value, str):
                print(
                    f"FAIL: sample {sample_id}: pipeline produced no report path",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            report_file = Path(report_path_value)
            if not report_file.is_file():
                print(
                    f"FAIL: sample {sample_id}: pipeline produced no archived report",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            report_hash_check = report.get("email_sha256")
            if report_hash_check is not None and str(report_hash_check) != str(gold_row["raw_sha256"]):
                print(
                    f"FAIL (gold/raw mismatch): sample {sample_id}: report "
                    f"email_sha256 {report_hash_check} != raw_sha256 "
                    f"{gold_row['raw_sha256']}",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            control_b = None
            if report.get("gate_decision") == "complex" and final_state.get("parsed") is not None:
                control_b = run_control_b(
                    settings,
                    final_state,
                    report_file.parent / "responses_control_b",
                    pricing,
                )
            evaluation_row = build_evaluation_row(
                gold_row,
                report,
                final_state,
                report_file,
                control_b,
                pricing,
                variant,
                split,
                measurement_scope,
            )
            rows.append(evaluation_row)
            if _row_internal_ok(evaluation_row):
                any_internal_ok = True
            consecutive_infra_failures = _infra_guard(
                evaluation_row, consecutive_infra_failures
            )
            if _abort_on_systematic_outage(
                sample_profile, consecutive_infra_failures, any_internal_ok
            ):
                print(
                    "FAIL: systematic provider failure detected "
                    f"({consecutive_infra_failures} consecutive samples with a "
                    "failed INTERNAL attempt and no successful internal call "
                    "so far; full-corpus scope, the bounded smoke never aborts "
                    "on provider outcomes) — aborting before burning the "
                    "corpus; fix the runtime and rerun the SAME frozen "
                    "baseline",
                    file=sys.stderr,
                )
                return EXIT_FAIL
            print(
                f"[{index + 1}/{len(run_rows)}] {sample_id} "
                f"gate={evaluation_row['gate_decision']} "
                f"pred={evaluation_row['predicted']} "
                f"action={evaluation_row['recommended_action']}"
            )
    finally:
        temp_dir.cleanup()

    metrics = evaluate_metrics(
        run_rows,
        _reports_for_metrics(rows),
        sample_extras=extras_from_rows(rows),
        controls=controls_from_rows(rows),
    )
    metrics["limitations"] = list(metrics["limitations"]) + list(
        evaluation_config.published_limitations
    )

    # --- paired artifact: ONLY when both series are exactly the same samples --
    paired_payload: dict[str, Any] | None = None
    if paired is not None and rag_ablation is not None:
        try:
            paired_payload = build_paired_baseline_payload(
                paired, run_rows, rows, rag_ablation
            )
        except PairedRunError as error:
            print(f"FAIL: {error}", file=sys.stderr)
            return EXIT_FAIL

    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = build_manifest(
        settings=settings,
        evaluation_config=evaluation_config,
        evaluation_config_path=Path(args.evaluation_config),
        experiment_lock_path=Path(args.experiment_lock),
        gold_path=gold_path,
        gold_rows=gold_rows,
        out_dir=out_dir,
        variant=variant,
        split=split,
        rows=rows,
        started_at=started_at,
        mode="live",
        measurement_scope=measurement_scope,
        performance_claims_allowed=performance_claims_allowed,
        sample_selection_rule=SAMPLE_SELECTION_RULE,
        selected_ids=selected_ids,
        full_support=full_support,
        rag_ablation=(
            build_rag_ablation_block(rag_ablation, paired)
            if rag_ablation is not None and paired is not None
            else None
        ),
    )
    if paired_payload is not None:
        # The full paired diagnostic is also embedded in the manifest/report;
        # the standalone artifact carries the exact read-only provenance.
        manifest["paired_baseline"] = paired_payload
    write_predictions_atomic(out_dir / "predictions.jsonl", rows)
    write_json_atomic(out_dir / "metrics.json", metrics)
    write_json_atomic(out_dir / "manifest.json", manifest)
    write_matrix_csv(out_dir / "matrix.csv", metrics)
    write_human_report(out_dir / "report.md", metrics, manifest)
    if paired_payload is not None:
        write_json_atomic(out_dir / "paired_baseline.json", paired_payload)
    invalid_abc = [
        row["sample_id"]
        for row in rows
        if row["abc_audit"]["applicable"] and not row["abc_audit"]["valid"]
    ]
    if invalid_abc:
        print(
            "FAIL: A/B/C audit invalid for sample(s): " + ", ".join(invalid_abc),
            file=sys.stderr,
        )
        return EXIT_FAIL
    print(f"live {variant} complete: {out_dir}")
    return EXIT_OK


def _abort_on_systematic_outage(
    sample_profile: str, consecutive_failures: int, any_internal_ok: bool
) -> bool:
    """True only for a FULL-corpus run that never saw ONE successful INTERNAL call.

    Operator amendment 2026-09-21: the bounded smoke is a harness-validation
    gate — provider timeout/unavailable outcomes stay honest rows in the
    denominator and never abort it, even when all smoke records fail (five
    genuine timeouts must not invalidate G6). The full T19E run keeps the
    early abort so a dead endpoint cannot burn 83 emails without a single
    real model result.
    """

    return (
        sample_profile == FULL_PROFILE
        and consecutive_failures >= CONSECUTIVE_INFRA_FAILURE_LIMIT
        and not any_internal_ok
    )


def _infra_guard(
    evaluation_row: Mapping[str, Any], current: int
) -> int:
    """Consecutive-failure counter for SYSTEMATIC provider outages.

    A hard outage (e.g. every call 401) fails every INTERNAL attempt from
    the very first sample. Legitimate endpoint latency VARIANCE (some calls
    succeed near the frozen phase budgets, others time out) must never
    abort a run. ``_abort_on_systematic_outage`` decides from this counter;
    it only ever fires for a FULL-corpus run whose first
    CONSECUTIVE_INFRA_FAILURE_LIMIT records all failed with no internal
    success yet.
    """

    if _row_internal_ok(evaluation_row):
        return 0
    return current + 1


def _row_internal_ok(evaluation_row: Mapping[str, Any]) -> bool:
    internal_calls = [
        call
        for call in evaluation_row.get("llm_calls") or []
        if isinstance(call, Mapping) and call.get("phase") == "internal"
    ]
    return any(call.get("status") == "ok" for call in internal_calls)


def _reports_for_metrics(rows: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The archived report dicts (reloaded from disk: authentic artifacts)."""

    reports: list[dict[str, Any]] = []
    for row in rows:
        report = json.loads((PROJECT_ROOT / row["report_path"]).read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise RuntimeError(f"archived report for {row['sample_id']} is not an object")
        reports.append(report)
    return reports


#: A pipeline exception aborts the run loudly (never a row without an
#: archived report); therefore no synthetic failure report exists here.



# ---------------------------------------------------------------------------
# RECOMPUTE mode (offline; no provider call, no external network)
# ---------------------------------------------------------------------------


def run_recompute(args: argparse.Namespace, evaluation_config: EvaluationConfig) -> int:
    """Recompute metrics from archived authentic artifacts only.

    No provider call and no external network access: the gold_dev partition
    (metadata only), the archived evaluation rows and the archived authentic
    per-sample reports are reloaded and the metrics are recalculated
    deterministically. Original observation timestamps/provenance are
    preserved; live latency/availability of the recompute day is never
    pretended. The recomputed metrics must equal the live metrics exactly.
    """

    from_run = Path(args.from_run)
    if not from_run.is_absolute():
        from_run = PROJECT_ROOT / from_run
    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = PROJECT_ROOT / out_dir
    if not (from_run / "predictions.jsonl").is_file() or not (from_run / "manifest.json").is_file():
        print(
            f"FAIL: --from-run {from_run} is not an archived evaluation run "
            "(predictions.jsonl/manifest.json missing)",
            file=sys.stderr,
        )
        return EXIT_FAIL
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"FAIL: --out directory is not empty: {out_dir}", file=sys.stderr)
        return EXIT_FAIL

    manifest = json.loads((from_run / "manifest.json").read_text(encoding="utf-8"))
    split = str(manifest["split"])
    if split == FORBIDDEN_SPLIT:
        print("BLOCKED: gold_test recomputation is not part of TICKET-14", file=sys.stderr)
        return EXIT_BLOCKED

    rows_raw: list[dict[str, Any]] = []
    with (from_run / "predictions.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    print("FAIL: archived prediction row is not a JSON object", file=sys.stderr)
                    return EXIT_FAIL
                rows_raw.append(row)
    if not rows_raw:
        print(f"FAIL: archived run {from_run} has no evaluation rows", file=sys.stderr)
        return EXIT_FAIL

    gold_rows, gold_path = load_gold_records(evaluation_config, split)
    by_sample = {str(row["sample_id"]): row for row in gold_rows}
    measurement_scope = str(manifest.get("measurement_scope", "full_dev_baseline"))
    if measurement_scope == "smoke":
        selected_ids = manifest.get("selected_sample_ids")
        if not isinstance(selected_ids, list) or not selected_ids:
            print(
                "FAIL: smoke run manifest has no selected_sample_ids; the "
                "archived selection cannot be verified against the "
                "deterministic rule",
                file=sys.stderr,
            )
            return EXIT_FAIL
        expected_ids = sorted(
            str(row["sample_id"]) for row in select_smoke_sample(gold_rows)
        )
        archived_ids = sorted(str(value) for value in selected_ids)
        if expected_ids != archived_ids:
            print(
                "FAIL: archived selected_sample_ids differ from the "
                "deterministic selection recomputed from gold_dev "
                f"({expected_ids} vs {archived_ids})",
                file=sys.stderr,
            )
            return EXIT_FAIL
        missing_selected = [value for value in expected_ids if str(value) not in {str(row["sample_id"]) for row in rows_raw}]
        if missing_selected:
            print(
                "FAIL: archived smoke run is missing selected sample row(s): "
                f"{missing_selected} (the smoke must reproduce exactly the "
                "deterministic selection)",
                file=sys.stderr,
            )
            return EXIT_FAIL
        extra_rows = [
            str(row["sample_id"])
            for row in rows_raw
            if str(row["sample_id"]) not in set(expected_ids)
        ]
        if extra_rows:
            print(
                "FAIL: archived smoke run contains row(s) outside the "
                f"deterministic selection: {extra_rows}",
                file=sys.stderr,
            )
            return EXIT_FAIL
        gold_rows_aligned = [by_sample[str(row["sample_id"])] for row in rows_raw]
    elif measurement_scope == "full_dev_baseline":
        missing = [str(row["sample_id"]) for row in rows_raw if str(row["sample_id"]) not in by_sample]
        if missing:
            print(
                f"FAIL: archived rows reference samples outside {split}: {missing[:5]}",
                file=sys.stderr,
            )
            return EXIT_FAIL
        if len(rows_raw) != len(gold_rows):
            print(
                f"FAIL: archived row count {len(rows_raw)} != gold {split} record "
                f"count {len(gold_rows)} (denominators must stay complete)",
                file=sys.stderr,
            )
            return EXIT_FAIL
        gold_rows_aligned = [by_sample[str(row["sample_id"])] for row in rows_raw]
    else:
        print(f"FAIL: unknown measurement_scope in archived manifest: {measurement_scope!r}",
              file=sys.stderr)
        return EXIT_FAIL

    # Provenance integrity: every archived report must still hash-match.
    reports: list[dict[str, Any]] = []
    for row in rows_raw:
        report_file = from_run / row["report_dir"] / "report.json"
        if not report_file.is_file():
            print(f"FAIL: archived report missing: {report_file}", file=sys.stderr)
            return EXIT_FAIL
        if _file_sha256(report_file) != row["report_sha256"]:
            print(
                f"FAIL: archived report hash mismatch for {row['sample_id']} "
                f"({report_file})",
                file=sys.stderr,
            )
            return EXIT_FAIL
        report = json.loads(report_file.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            print(f"FAIL: archived report not an object for {row['sample_id']}", file=sys.stderr)
            return EXIT_FAIL
        reports.append(report)

    metrics = evaluate_metrics(
        gold_rows_aligned,
        reports,
        sample_extras=extras_from_rows(rows_raw),
        controls=controls_from_rows(rows_raw),
    )
    metrics["limitations"] = list(metrics["limitations"]) + list(
        evaluation_config.published_limitations
    )

    live_metrics: dict[str, Any] | None = None
    live_metrics_path = from_run / "metrics.json"
    if live_metrics_path.is_file():
        try:
            live_metrics = json.loads(live_metrics_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            live_metrics = None
    differences: list[str] = []
    if live_metrics is not None:
        differences = diff_metrics(live_metrics, metrics)
        if differences:
            print(
                "FAIL: recomputed metrics differ from the live metrics:\n  - "
                + "\n  - ".join(differences[:20]),
                file=sys.stderr,
            )
            write_json_atomic(out_dir / "metrics.json", metrics)
            return EXIT_FAIL

    recompute_manifest = {
        "schema_version": "recompute-manifest-1.0",
        "recomputed_from_run": str(from_run),
        "measurement_scope": measurement_scope,
        "source_manifest": {
            "run_id": manifest.get("run_id"),
            "date_time_utc": manifest.get("date_time_utc"),
            "git_commit": manifest.get("git_commit"),
            "model": manifest.get("model"),
            "variant": manifest.get("variant"),
            "split": manifest.get("split"),
            "sample_count": manifest.get("sample_count"),
            "measurement_scope": manifest.get("measurement_scope"),
            "performance_claims_allowed": manifest.get("performance_claims_allowed"),
            "sample_selection_rule": manifest.get("sample_selection_rule"),
            "selected_sample_ids": manifest.get("selected_sample_ids"),
            "full_dev_label_support": manifest.get("full_dev_label_support"),
        },
        "recomputed_at_utc": datetime.now(UTC).isoformat(),
        "network_calls": 0,
        "provider_calls": 0,
        "observation_timestamps_preserved": True,
        "note": (
            "offline recompute: reproduces the METRICS exactly from the "
            "archived authentic responses/results; it does not reproduce "
            "live latency or provider availability and does not replace "
            "the live run"
        ),
        "recomputation_metadata_keys": [
            "recomputed_at_utc",
            "recomputed_from_run",
            "source_manifest",
            "network_calls",
            "provider_calls",
            "observation_timestamps_preserved",
            "note",
            "recomputation_metadata_keys",
        ],
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json_atomic(out_dir / "metrics.json", metrics)
    write_json_atomic(out_dir / "manifest.json", recompute_manifest)
    write_matrix_csv(out_dir / "matrix.csv", metrics)
    write_human_report(out_dir / "report.md", metrics, manifest)
    print(
        f"recompute complete: {out_dir} (equal to live metrics; "
        f"scope={measurement_scope}, sample_count={len(rows_raw)})"
    )
    return EXIT_OK


def diff_metrics(original: Mapping[str, Any], recomputed: Mapping[str, Any]) -> list[str]:
    """Deep comparison of two metrics payloads (float-exact, order-sensitive)."""

    def _walk(left: Any, right: Any, path: str, problems: list[str]) -> None:
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            for key in sorted(set(left) | set(right)):
                if key not in left:
                    problems.append(f"{path}.{key}: missing in live metrics")
                elif key not in right:
                    problems.append(f"{path}.{key}: missing in recomputed metrics")
                else:
                    _walk(left[key], right[key], f"{path}.{key}", problems)
            return
        if isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                problems.append(f"{path}: list length {len(left)} != {len(right)}")
                return
            for index, (item_left, item_right) in enumerate(zip(left, right)):
                _walk(item_left, item_right, f"{path}[{index}]", problems)
            return
        if left != right:
            problems.append(f"{path}: {left!r} != {right!r}")

    problems: list[str] = []
    _walk(original, recomputed, "$", problems)
    return problems


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "TICKET-14 dev baseline evaluation (live) and exact offline "
            "recompute (docs/evaluation.md §8.6)"
        )
    )
    parser.add_argument("--split", choices=["dev", FORBIDDEN_SPLIT], default="dev")
    parser.add_argument("--mode", choices=["live", "recompute"], default="live")
    parser.add_argument("--variant", default=BASELINE_VARIANT)
    parser.add_argument(
        "--paired-with",
        default=None,
        help=(
            "archived baseline run directory compared against --variant rag "
            "(read-only: never replayed, never modified). Required for "
            "--variant rag; refused otherwise (docs/evaluation.md §8.7)."
        ),
    )
    parser.add_argument(
        "--sample-profile",
        default=None,
        choices=[SMOKE_PROFILE, FULL_PROFILE],
        help=(
            "live measurement scope: 'smoke' = deterministic representative "
            "harness sample (one lexicographically first record per dev "
            "label with support>0; diagnostic only); 'full' = complete "
            "gold_dev evaluation, reserved for TICKET-19E. Required for "
            "--mode live."
        ),
    )
    parser.add_argument("--out", default=None, help="output run directory")
    parser.add_argument("--from-run", default=None, help="archived run for recompute")
    parser.add_argument(
        "--evaluation-config",
        default=str(PROJECT_ROOT / "configs" / "evaluation.yaml"),
    )
    parser.add_argument(
        "--experiment-lock",
        default=str(PROJECT_ROOT / "configs" / "experiment_lock.json"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        evaluation_config = load_evaluation_config(Path(args.evaluation_config))
    except (OSError, ValueError, ValidationError, ExperimentLockError) as error:
        print(f"FAIL: evaluation configuration: {error}", file=sys.stderr)
        return EXIT_FAIL
    if args.mode == "recompute":
        if not args.from_run or not args.out:
            print(
                "FAIL: --mode recompute requires --from-run and --out",
                file=sys.stderr,
            )
            return EXIT_FAIL
        return run_recompute(args, evaluation_config)
    # live
    if not args.out:
        print("FAIL: --mode live requires --out", file=sys.stderr)
        return EXIT_FAIL
    if not args.sample_profile:
        print(
            "FAIL: --mode live requires an explicit --sample-profile "
            f"({SMOKE_PROFILE} or {FULL_PROFILE}); an accidental full "
            "corpus benchmark is refused (full scope is reserved for "
            "TICKET-19E)",
            file=sys.stderr,
        )
        return EXIT_FAIL
    if args.split == FORBIDDEN_SPLIT:
        print(
            "BLOCKED: gold_test.jsonl must not be opened by the TICKET-14 dev "
            "workflow; the terminal test evaluation belongs to the later "
            "authorized ticket",
            file=sys.stderr,
        )
        return EXIT_BLOCKED
    try:
        lock = load_experiment_lock(Path(args.experiment_lock))
    except (OSError, json.JSONDecodeError, ExperimentLockError) as error:
        print(f"FAIL: experiment lock: {error}", file=sys.stderr)
        return EXIT_FAIL
    try:
        return run_live(args, evaluation_config, lock)
    except (ExperimentLockError, build_corpus.GoldValidationError, GoldTestAccessRefused) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
