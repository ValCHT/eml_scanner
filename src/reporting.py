"""Report assembly, deterministic summary and atomic writing (TICKET-11).

Owns two frozen interfaces of docs/tickets/TICKET-11.md:

- ``build_report(state, services) -> TriageReport``: deterministic projection of
  the final ``EmailTriageState`` onto the frozen
  ``schemas/triage_report.schema.json`` shape (docs/contracts.md §2.6). The
  report carries only typed facts and registry-backed rendered phrases; no free
  text is promoted to a fact and no provider response is paraphrased.
- ``write_report(report, directory) -> Path``: strict schema validation, then
  an atomic write of ``report.json`` + ``summary.txt`` (+ optional
  ``events.jsonl``). An existing target is never overwritten silently: the
  writer raises ``ReportWriteError`` and the caller exits non-zero instead of
  announcing a saved report.

The French ``analyst_summary`` is rendered exclusively from deterministic
templates (no third LLM call), bounded to 100 words, with untrusted text
escaped and dangerous URLs defanged for reading; exact values stay only in the
restricted JSON report.
"""

from __future__ import annotations

import hashlib
import html
import json
import math
import os
import platform
import re
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .llm import validate_against_schema
from .state import Assessment, EmailTriageState, Evidence
from .verify import compute_verdict_confidence, confidence_margin

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids an import cycle
    from .graph import Services

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "triage_report.schema.json"

#: Triage report as a plain JSON object (the frozen schema is the contract).
TriageReport = dict[str, Any]

#: Hard bound of the rendered summary (docs/contracts.md §2.6: ≤ 100 mots).
SUMMARY_MAX_WORDS = 100

#: Bound of one rendered untrusted text fragment in the summary.
SUMMARY_TEXT_LIMIT = 80

#: Secret-like patterns refused/expurgated before anything is written.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"(?i)authorization\s*:\s*Bearer\s+\S+",
        r"(?i)x-apikey\s*:\s*\S+",
        r'(?i)"(?:api[_-]?key|access[_-]?token|secret|token|password|authorization)"\s*:\s*"[^"]*"',
        r"(?i)\b(api[_-]?key|access[_-]?token|token|secret|password)\s*[=:]\s*\S+",
        r"sk-[A-Za-z0-9]{8,}",
        r"akml-[A-Za-z0-9_\-]{4,}",
    )
)


class ReportWriteError(RuntimeError):
    """Explicit refusal to write a report (never a silent overwrite)."""


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _percent(value: float) -> str:
    return f"{value * 100:.0f}%"


def _finite(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _bounded_text(value: object, limit: int = SUMMARY_TEXT_LIMIT) -> str:
    """Escape and bound one untrusted fragment for plain-text rendering."""

    if value is None:
        return ""
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return html.escape(text, quote=True)


def defang_url(value: str) -> str:
    """Defang an URL for reading (the exact value stays in the JSON report)."""

    out = value.strip()
    out = re.sub(r"(?i)^http:", "hxxp:", out)
    out = re.sub(r"(?i)^https:", "hxxps:", out)
    # Host dots only: keep scheme/port/path separators readable-bound.
    head, sep, tail = out.partition("://")
    if sep:
        host_part, slash, rest = tail.partition("/")
        host_part = host_part.replace(".", "[.]")
        out = f"{head}{sep}{host_part}{slash}{rest}"
    return html.escape(out, quote=True)


def defang_text(value: str) -> str:
    """Defang every http(s) URL found in a free text fragment."""

    return re.sub(
        r"(?i)\bhttps?://[^\s\"'<>]+",
        lambda match: defang_url(match.group(0)),
        value,
    )


def _code_commit() -> str | None:
    """Best-effort HEAD commit of the working tree; None when unavailable."""

    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def _load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_report_schema() -> dict[str, Any]:
    schema = _load_json_file(REPORT_SCHEMA_PATH)
    if schema is None:  # pragma: no cover - the schema ships with the repo
        raise ReportWriteError(f"report schema unreadable: {REPORT_SCHEMA_PATH}")
    return _expand_type_lists(schema)


def _expand_type_lists(node: Any) -> Any:
    """Rewrite ``"type": [a, b]`` as an equivalent ``anyOf`` for the local
    validator (``src.llm.validate_against_schema`` supports ``anyOf`` but not
    a list of types; the frozen report schema uses one for ``Evidence.value``).
    Sibling constraints are merged into every variant.
    """

    if isinstance(node, dict):
        processed = {
            key: _expand_type_lists(value)
            for key, value in node.items()
            if not (key == "type" and isinstance(value, list))
        }
        type_list = node.get("type")
        if isinstance(type_list, list):
            return {
                "anyOf": [{**processed, "type": item} for item in type_list]
            }
        return processed
    if isinstance(node, list):
        return [_expand_type_lists(item) for item in node]
    return node


# ---------------------------------------------------------------------------
# Verdict / comparison projection
# ---------------------------------------------------------------------------


def _assessment_verdict(assessment: Assessment | None) -> tuple[str | None, float | None]:
    if assessment is None:
        return None, None
    vector = assessment.model_dump()["probabilities"]
    if not all(_finite(value) for value in vector.values()):
        return None, None
    verdict, confidence = compute_verdict_confidence(vector)
    return verdict, confidence


def _probabilities_dump(assessment: Assessment | None) -> dict[str, float] | None:
    if assessment is None:
        return None
    return {key: float(value) for key, value in assessment.model_dump()["probabilities"].items()}


def _run_status(
    internal: Assessment | None,
    final_validated: Assessment | None,
    final_source: str,
) -> str:
    """Honest run status (docs/contracts.md §2.6).

    - ``error``: no validated assessment survives (both phases unavailable);
    - ``degraded``: a documented degradation — internal fallback or a missing
      INTERNAL assessment while a FINAL result exists;
    - ``ok``: both phases have a valid assessment and the FINAL is real.
    """

    if final_validated is None and internal is None:
        return "error"
    if final_validated is None:
        return "error"
    if final_source == "internal_fallback" or internal is None:
        return "degraded"
    return "ok"


def _verdict_changed(internal: str | None, final: str | None) -> bool | None:
    """bool only when both verdicts exist (docs/contracts.md §2.6)."""

    if internal is None or final is None:
        return None
    return internal != final


def _cost_projection(
    records: list[Any],
) -> tuple[float | None, str]:
    """Aggregate usage cost: never zero for an unknown invoice (§1.4)."""

    if not records:
        return None, "unknown"
    known = [record for record in records if record.cost_usd is not None]
    if not known:
        return None, "unknown"
    total = float(sum(record.cost_usd for record in known))
    if len(known) < len(records):
        return total, "partial"
    statuses = {record.cost_status for record in known}
    if len(statuses) == 1:
        status = statuses.pop()
        return total, status
    return total, "partial"


# ---------------------------------------------------------------------------
# Trusted phrases generated by code from registry IDs (never free model text)
# ---------------------------------------------------------------------------


def _evidence_phrase(evidence: Evidence | None, evidence_id: str) -> str:
    if evidence is None:
        return f"référence {evidence_id} absente du registre"
    value = evidence.value
    if isinstance(value, float):
        rendered = f"{value:g}"
    else:
        rendered = str(value)
    phrase = (
        f"{evidence.predicate} ({evidence.provenance}) "
        f"depuis {evidence.source_ref} = {rendered[:120]}"
    )
    return _bounded_text(defang_text(phrase), 140)


def _decisive_evidence(state: EmailTriageState) -> tuple[list[str], list[str]]:
    assessment = state.final_validated
    ids = list(assessment.decisive_evidence_ids) if assessment is not None else []
    phrases = [
        _evidence_phrase(state.evidence.get(evidence_id), evidence_id)
        for evidence_id in ids
    ]
    return ids, phrases


def _material_limitation(state: EmailTriageState) -> str:
    """Principal limitation, from typed facts only (docs/decisions.md §4.3)."""

    if state.parsed is None:
        first = next(
            (issue for issue in state.errors if issue.source == "parse"),
            None,
        )
        return f"parsing impossible ({first.code if first else 'parse_error'})"
    if state.final_source == "internal_fallback":
        return "appel FINAL indisponible, copie INTERNE utilisée"
    if state.final_source == "none":
        return "aucune évaluation finale valide"
    assessment = state.final_validated or state.internal
    if assessment is not None and assessment.missing_information:
        return "informations manquantes : " + ", ".join(assessment.missing_information)
    parser_issues = [issue for issue in state.errors if issue.source == "parse"]
    if parser_issues:
        return "défaut de parsing : " + parser_issues[0].code
    return "aucune limite matérielle signalée"


def _reason_codes(state: EmailTriageState) -> str:
    assessment = state.final_validated or state.internal
    if assessment is None:
        return "aucun code de raison validé"
    codes: list[str] = []
    for inference in assessment.inferences:
        if inference.code not in codes:
            codes.append(inference.code)
    if not codes:
        return "aucun code de raison validé"
    return ", ".join(codes[:4])


# ---------------------------------------------------------------------------
# Deterministic French summary (six rubriques, ≤ 100 words, no active HTML)
# ---------------------------------------------------------------------------


def render_summary(state: EmailTriageState) -> str:
    """Render the analyst summary from templates and registry-backed facts."""

    parsed = state.parsed
    subject = _bounded_text(parsed.subject if parsed is not None else None) or "(sans objet)"
    sender = "(expéditeur inconnu)"
    if parsed is not None and parsed.from_addresses:
        sender = _bounded_text(parsed.from_addresses[0])

    internal_verdict, internal_confidence = _assessment_verdict(state.internal)
    final_verdict, final_confidence = _assessment_verdict(state.final_validated)
    if final_verdict is not None and final_confidence is not None:
        verdict_part = f"Verdict final {final_verdict} ({_percent(final_confidence)})"
        if internal_verdict is not None and internal_confidence is not None:
            verdict_part += (
                f", INTERNE {internal_verdict} ({_percent(internal_confidence)})"
            )
    elif internal_verdict is not None and internal_confidence is not None:
        verdict_part = (
            f"Verdict INTERNE {internal_verdict} ({_percent(internal_confidence)}), "
            "aucune évaluation finale valide"
        )
    else:
        verdict_part = "Verdict indéterminé, aucune évaluation valide"

    _, decisive_phrases = _decisive_evidence(state)
    strongest = decisive_phrases[0] if decisive_phrases else "aucune preuve décisive retenue"

    parts = [
        f"Objet : {subject} — Expéditeur : {sender}.",
        verdict_part + ".",
        f"Codes : {_reason_codes(state)}.",
        f"Preuve principale : {strongest}.",
        f"Limite : {_material_limitation(state)}.",
        f"Action recommandée : {state.action}"
        + (f" ({_bounded_text(state.policy_reasons[0])})" if state.policy_reasons else "")
        + ".",
    ]
    summary = " ".join(parts)
    words = summary.split()
    if len(words) > SUMMARY_MAX_WORDS:
        summary = " ".join(words[:SUMMARY_MAX_WORDS])
    return defang_text(summary)


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def _apply_assessment_categories(
    state: EmailTriageState,
) -> list[dict[str, Any]]:
    """Accepted observables enriched with the validated final categories."""

    assessment = state.final_validated
    categories: dict[str, Any] = {}
    if assessment is not None:
        categories = {
            entry.observable_id: entry for entry in assessment.observable_assessments
        }
    rendered: list[dict[str, Any]] = []
    for observable in state.accepted_observables:
        entry = categories.get(observable.id)
        update: dict[str, Any] = {}
        if entry is not None:
            update["category"] = entry.category
            update["justification"] = entry.reason_code
        if update:
            observable = observable.model_copy(update=update)
        rendered.append(observable.model_dump(mode="json"))
    return rendered


def _verification_projection(
    state: EmailTriageState,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Report issues: critical → unsupported claims, the rest → warnings.

    Typed state errors (parser/LLM/fallback/merge) are part of the audit and
    are included first; exact duplicates are collapsed.
    """

    unsupported: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    def _add(issue: Any, bucket: list[dict[str, Any]]) -> None:
        key = (issue.code, issue.severity, issue.source, issue.object_id, issue.message)
        if key in seen:
            return
        seen.add(key)
        bucket.append(issue.model_dump(mode="json"))

    for issue in state.errors:
        _add(issue, unsupported if issue.severity == "critical" else warnings)
    for issue in state.verification:
        _add(issue, unsupported if issue.severity == "critical" else warnings)
    return unsupported, warnings


def _reproducibility(state: EmailTriageState, services: "Services") -> dict[str, Any]:
    dependencies = PROJECT_ROOT / "requirements.lock"
    prompt_internal = PROJECT_ROOT / "prompts" / "internal_assessment.txt"
    prompt_final = PROJECT_ROOT / "prompts" / "final_assessment.txt"
    assessment_schema = PROJECT_ROOT / "schemas" / "assessment.schema.json"
    return {
        "code_commit": _code_commit(),
        "python_version": platform.python_version(),
        "dependencies_sha256": _sha256_file(dependencies) if dependencies.is_file() else "",
        "prompt_internal_sha256": _sha256_file(prompt_internal) if prompt_internal.is_file() else "",
        "prompt_final_sha256": _sha256_file(prompt_final) if prompt_final.is_file() else "",
        "assessment_schema_sha256": _sha256_file(assessment_schema) if assessment_schema.is_file() else "",
        "config_sha256": state.config_sha256,
        "corpus_split_sha256": None,
        "mode": services.mode,
        "started_at": state.started_at,
    }


def build_report(
    state: EmailTriageState,
    services: "Services",
    *,
    report_started_monotonic: float,
) -> TriageReport:
    """Project the final state onto the frozen report schema (§2.6).

    ``report_started_monotonic`` is the monotonic timestamp at which the
    ``write_report`` node began; ``report_ms`` measures its assembly and
    ``total_ms`` measures the whole run up to this report projection.
    """

    if state.gate is None:
        raise ReportWriteError("gate result missing: the pipeline did not complete")

    clock = services.clock
    report_ms = round((clock() - report_started_monotonic) * 1000.0, 3)
    total_ms = round((clock() - services.started_monotonic) * 1000.0, 3)
    timings = state.timings.model_copy(
        update={"report_ms": report_ms, "total_ms": total_ms}
    ).model_dump(mode="json")

    internal_verdict, internal_confidence = _assessment_verdict(state.internal)
    final_verdict, final_confidence = _assessment_verdict(state.final_validated)
    records = [record for record in (state.internal_call, state.final_call) if record is not None]
    cost_usd, cost_status = _cost_projection(records)
    decisive_ids, decisive_phrases = _decisive_evidence(state)
    unsupported, warnings = _verification_projection(state)
    assessment = state.final_validated

    report: TriageReport = {
        "schema_version": state.schema_version,
        "run_id": state.run_id,
        "email_sha256": state.parsed.email_sha256 if state.parsed is not None else None,
        "run_status": _run_status(state.internal, state.final_validated, state.final_source),
        "internal_verdict": internal_verdict,
        "internal_confidence": internal_confidence,
        "internal_probabilities": _probabilities_dump(state.internal),
        "gate_decision": state.gate.decision,
        "gate_reasons": list(state.gate.reasons),
        "enrichment": state.enrichment.model_dump(mode="json"),
        "visual_evidence": [entry.model_dump(mode="json") for entry in state.visual_evidence],
        "final_verdict": final_verdict,
        "final_confidence": final_confidence,
        "final_probabilities": _probabilities_dump(state.final_validated),
        "final_source": state.final_source,
        "verdict_changed": _verdict_changed(internal_verdict, final_verdict),
        "decisive_evidence": decisive_phrases,
        "decisive_evidence_ids": decisive_ids,
        "evidence": [entry.model_dump(mode="json") for entry in state.evidence.values()],
        "observables": _apply_assessment_categories(state),
        "inferences": (
            [entry.model_dump(mode="json") for entry in assessment.inferences]
            if assessment is not None
            else []
        ),
        "unsupported_claims": unsupported,
        "verification_warnings": warnings,
        "recommended_action": state.action,
        "policy_reasons": list(state.policy_reasons),
        "analyst_summary": render_summary(state),
        "timings": timings,
        "llm_calls": [record.model_dump(mode="json") for record in records],
        "cost_usd": cost_usd,
        "cost_status": cost_status,
        "reproducibility": _reproducibility(state, services),
    }
    # Defense in depth (docs/contracts.md §2.7): mask secret-like patterns in
    # the in-memory projection itself, so the returned report, report.json and
    # summary.txt are byte-consistent (write_report masks again defensively).
    report = _expurgate_structure(report)
    problems = validate_report(report)
    if problems:
        raise ReportWriteError("report does not satisfy the frozen schema: " + "; ".join(problems[:8]))
    return report


# ---------------------------------------------------------------------------
# Events (JSONL audit trail of the sequential pipeline)
# ---------------------------------------------------------------------------


def _tool_status_rows(results: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "query": result.query_observable_id,
            "status": result.status,
            "reason": result.reason,
            "requests_sent": result.requests_sent,
        }
        for result in results
    ]


def build_events(state: EmailTriageState, report_path: str | None = None) -> list[dict[str, Any]]:
    """One deterministic line per node in the frozen pipeline order."""

    enrichment = state.enrichment
    verification_codes = [issue.code for issue in state.verification]
    return [
        {
            "node": "parse_email",
            "status": "ok" if state.parsed is not None else "error",
            "ms": state.timings.parse_ms,
            "email_sha256": state.parsed.email_sha256 if state.parsed is not None else None,
        },
        {
            "node": "internal_assessment",
            "status": "ok" if state.internal is not None else "error",
            "ms": state.timings.internal_llm_ms,
            "attempts": state.internal_call.attempts if state.internal_call else 0,
        },
        {
            "node": "complexity_gate",
            "status": state.gate.decision if state.gate else "missing",
            "ms": state.timings.gate_ms,
            "reasons": list(state.gate.reasons) if state.gate else [],
        },
        {
            "node": "virustotal",
            "status": "skipped" if not enrichment.virustotal else "ran",
            "ms": state.timings.vt_ms,
            "results": _tool_status_rows(enrichment.virustotal),
        },
        {
            "node": "opencti",
            "status": "skipped" if not enrichment.opencti else "ran",
            "ms": state.timings.opencti_ms,
            "results": _tool_status_rows(enrichment.opencti),
        },
        {
            "node": "urlscan",
            "status": "skipped" if not enrichment.urlscan else "ran",
            "ms": state.timings.urlscan_ms,
            "results": _tool_status_rows(enrichment.urlscan),
        },
        {
            "node": "rag_lookup",
            "status": "no_op",
            "ms": state.timings.rag_ms,
            "cases": len(enrichment.rag),
        },
        {
            "node": "merge_evidence",
            "status": "ok" if state.parsed is not None else "skipped",
            "ms": state.timings.merge_ms,
            "evidence": len(state.evidence),
            "observables": len(state.observable_registry),
        },
        {
            "node": "final_assessment",
            "status": state.final_source,
            "ms": state.timings.final_llm_ms,
            "attempts": state.final_call.attempts if state.final_call else 0,
        },
        {
            "node": "verify",
            "status": "ok" if state.final_validated is not None else "error",
            "ms": state.timings.verify_ms,
            "issues": verification_codes,
        },
        {
            "node": "policy",
            "status": state.action,
            "ms": state.timings.policy_ms,
            "reasons": list(state.policy_reasons),
        },
        {
            "node": "write_report",
            "status": "ok",
            "ms": state.timings.report_ms,
            "report_path": report_path,
        },
    ]


# ---------------------------------------------------------------------------
# Validation and writing
# ---------------------------------------------------------------------------


def _summary_problems(summary: object) -> list[str]:
    if not isinstance(summary, str) or not summary.strip():
        return ["analyst_summary is empty or not a string"]
    problems: list[str] = []
    words = summary.split()
    if len(words) > SUMMARY_MAX_WORDS:
        problems.append(f"analyst_summary has {len(words)} words (> {SUMMARY_MAX_WORDS})")
    lowered = summary.lower()
    if "<script" in lowered or "javascript:" in lowered or "<img" in lowered:
        problems.append("analyst_summary contains active HTML content")
    if re.search(r"(?i)\b(?:https?|hxxps?)://", summary):
        # Defanged forms only: a raw scheme with a dotted host is refused.
        for match in re.finditer(r"(?i)\bhttps?://([^\s/\"'<>]+)", summary):
            if "." in match.group(1) and "[.]" not in match.group(1):
                problems.append("analyst_summary contains a non-defanged URL")
                break
    return problems


def _timing_problems(report: Mapping[str, Any]) -> list[str]:
    timings = report.get("timings")
    if not isinstance(timings, dict):
        return ["timings is missing or not an object"]
    problems: list[str] = []
    for name, value in timings.items():
        if not _finite(value) or float(value) < 0:
            problems.append(f"timings.{name} is not a finite non-negative number")
    total = timings.get("total_ms")
    if _finite(total):
        phase_names = [name for name in timings if name != "total_ms"]
        phase_sum = sum(float(timings[name]) for name in phase_names if _finite(timings[name]))
        if float(total) + 0.02 < phase_sum:
            problems.append(
                f"timings.total_ms ({total}) is smaller than the phase sum ({phase_sum:.3f})"
            )
    return problems


def _consistency_problems(report: Mapping[str, Any]) -> list[str]:
    problems: list[str] = []
    run_status = report.get("run_status")
    final_source = report.get("final_source")
    if run_status == "error" and report.get("final_probabilities") is not None:
        problems.append("run_status=error with non-null final_probabilities")
    if final_source == "none" and report.get("final_probabilities") is not None:
        problems.append("final_source=none with non-null final_probabilities")
    final_verdict = report.get("final_verdict")
    internal_verdict = report.get("internal_verdict")
    changed = report.get("verdict_changed")
    if changed is not None:
        if final_verdict is None or internal_verdict is None:
            problems.append("verdict_changed is not null while a verdict is missing")
        elif changed != (final_verdict != internal_verdict):
            problems.append("verdict_changed contradicts the recorded verdicts")
    action = report.get("recommended_action")
    if action not in ("AUTO", "REVIEW", "ESCALATE"):
        problems.append(f"recommended_action {action!r} is not a contract value")
    return problems


def validate_report(report: object) -> list[str]:
    """Schema + invariant validation; never repairs the document."""

    if not isinstance(report, dict):
        return ["report: expected a JSON object"]
    problems = validate_against_schema(report, load_report_schema())
    if not problems:
        problems.extend(_summary_problems(report.get("analyst_summary")))
        problems.extend(_timing_problems(report))
        problems.extend(_consistency_problems(report))
    return problems


def _atomic_write(path: Path, data: bytes) -> None:
    """Same-directory temp file + os.replace; no partial target ever visible."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def expurgate_report_text(text: str) -> str:
    """Mask secret-like patterns in ONE plain-text value."""

    out = text
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub("[REDACTED]", out)
    return out


def _expurgate_structure(value: Any) -> Any:
    """Recursively mask secret-like patterns in string leaves.

    Applying the patterns to serialized JSON text could consume structural
    characters (``\\S+`` crosses quotes and commas) and corrupt the document;
    masking structurally first keeps the JSON well-formed by construction.
    """

    if isinstance(value, str):
        return expurgate_report_text(value)
    if isinstance(value, dict):
        return {key: _expurgate_structure(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expurgate_structure(item) for item in value]
    return value


def write_report(
    report: TriageReport,
    directory: Path | str,
    *,
    events: list[dict[str, Any]] | None = None,
    finalize: Callable[[TriageReport], None] | None = None,
) -> Path:
    """Validate and atomically write ``report.json`` (+ ``summary.txt``).

    ``finalize`` (optional) is applied to the in-memory document immediately
    before serialization so a caller can stamp the final measurements. An
    existing ``report.json``/``summary.txt``/``events.jsonl`` in ``directory``
    is NEVER overwritten silently: ``ReportWriteError`` is raised instead.
    """

    directory = Path(directory)
    if finalize is not None:
        finalize(report)
    problems = validate_report(report)
    if problems:
        raise ReportWriteError(
            "report refused (validation): " + "; ".join(problems[:8])
        )

    report_path = directory / "report.json"
    summary_path = directory / "summary.txt"
    events_path = directory / "events.jsonl"
    existing = [path for path in (report_path, summary_path, events_path) if path.exists()]
    if existing:
        raise ReportWriteError(
            "refusing to overwrite existing report artifact(s): "
            + ", ".join(str(path) for path in existing)
        )

    text = json.dumps(
        _expurgate_structure(report),
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )
    summary = report["analyst_summary"]
    if not isinstance(summary, str):
        raise ReportWriteError("analyst_summary is not a string")
    safe_summary = expurgate_report_text(summary)

    try:
        _atomic_write(report_path, text.encode("utf-8"))
        _atomic_write(summary_path, (safe_summary + "\n").encode("utf-8"))
        if events is not None:
            payload = "".join(
                json.dumps(_expurgate_structure(event), ensure_ascii=False, sort_keys=True) + "\n"
                for event in events
            )
            _atomic_write(events_path, payload.encode("utf-8"))
    except OSError as error:
        raise ReportWriteError(f"report write failed: {error}") from error
    return report_path


__all__ = [
    "REPORT_SCHEMA_PATH",
    "SUMMARY_MAX_WORDS",
    "ReportWriteError",
    "TriageReport",
    "build_events",
    "build_report",
    "defang_text",
    "defang_url",
    "load_report_schema",
    "render_summary",
    "validate_report",
    "write_report",
]
