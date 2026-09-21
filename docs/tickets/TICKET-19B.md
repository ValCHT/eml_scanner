# TICKET-19B — Agentic Core with Frozen V1 Tools

## STATUS / GATE

G8-B

## OBJECTIVE

Créer le graph V2 et permettre à Qwen de choisir dynamiquement entre VirusTotal, OpenCTI et urlscan, puis de terminer explicitement l’investigation.

Cette étape doit comparer une sélection agentique avec exactement le même arsenal principal que la V1, sans ajouter RAG, vision ou OSINT+.

## ARCHITECTURAL AUTHORITY / OVERRIDES

Les graph cycles sont autorisés uniquement dans `src/agentic_graph.py`.

Le V1 graph reste gelé.

Le modèle choisit l’action suivante, mais ne possède jamais le pouvoir d’exécution. Toute proposition passe par le validateur déterministe puis, si autorisée, par l’adaptateur V1 existant.

## PRECONDITIONS / DEPENDENCIES

- G8-A PASS and receipt verifies.
- TICKET-19A recorded DONE.
- Current branch is `experiment/t19-agentic-investigator`.
- `prompts/investigator.txt` and `configs/investigation.yaml` are frozen at the G8-A versions.
- Existing V1 adapters are present and their previous gates remain valid.

## REUSE FROM PREVIOUS TICKETS

Reuse directly:

- T03 parser.
- T04 `assess_internal()`.
- T05 `decide_gate()`.
- T06 `VirusTotalAdapter`.
- T07 `OpenCTIAdapter`.
- T08 `UrlscanAdapter`.
- T09 `merge_evidence()`, `assess_final()`, `final_selection()`.
- T10 `verify_assessment()`, `decide_policy()`.
- T11 `Services`, deadlines, run IDs, reporting.
- T19A native tool transport and contracts.

No provider/network code for VT/OpenCTI/urlscan may be duplicated.

## MUST NOT MODIFY

- `src/graph.py`
- `src/parsing.py`
- `src/gate.py`
- `src/tools/virustotal.py`
- `src/tools/opencti.py`
- `src/tools/urlscan.py`
- `src/policy.py`
- `src/llm.py`
- `prompts/internal_assessment.txt`
- `prompts/final_assessment.txt`
- `prompts/investigator.txt`
- `configs/gate.yaml`
- `configs/policy.yaml`
- `scripts/check_gate.py`
- Gold files

## IN SCOPE

- Investigator loop.
- Deterministic Tool Validator.
- Tool schemas for VT/OpenCTI/urlscan/finish.
- V1 adapter dispatch.
- Step result merge.
- Derived observable registration.
- Agentic graph.
- Agent audit and sidecar reporting.
- Agentic CLI entrypoint.
- Core real smoke.

## OUT OF SCOPE

- RAG.
- Vision.
- QR changes.
- RDAP.
- DNS.
- Certificate Transparency.
- Campaign intelligence.
- Gate threshold changes.
- V01–V16 changes.
- Policy changes.
- Benchmark architecture selection.

## FILES ALLOWED

Existing:

- `src/agentic_state.py`
- `src/investigator.py`
- `configs/investigation.yaml`
- `docs/contracts.md`
- `docs/architecture.md`
- `scripts/smoke_agentic.py`

New files listed below.

No other tracked file may be modified.

## NEW FILES

- `src/tool_validator.py`
- `src/agentic_graph.py`
- `src/agentic_reporting.py`
- `run_agentic.py`
- `tests/test_tool_validator.py`
- `tests/test_agentic_graph.py`
- `tests/test_agentic_reporting.py`

## EXISTING INTERFACES REUSED

Use the exact post-T18 signatures for:

- parser ;
- INTERNAL ;
- gate ;
- VT/OpenCTI/urlscan adapters ;
- evidence merge ;
- FINAL ;
- verifier ;
- policy ;
- report builder ;
- `LunaClient.complete_with_tools()` from T19A.

If an existing symbol name differs from an older ticket but provides the contracted capability, import the actual symbol; do not create a compatibility duplicate.

## NEW INTERFACES / EXACT SIGNATURES

In `src/tool_validator.py`:

```python
ToolValidationCode = Literal[
    "ALLOW",
    "DENY_MULTIPLE_CALLS",
    "DENY_INVALID_ARGUMENT",
    "DENY_UNKNOWN_TOOL",
    "DENY_UNKNOWN_OBSERVABLE",
    "DENY_UNKNOWN_VISUAL",
    "DENY_INCOMPATIBLE_TYPE",
    "DENY_PROVENANCE",
    "DENY_ROLE",
    "DENY_DEPTH",
    "DENY_PRIVACY",
    "DENY_EGRESS",
    "DENY_BUDGET",
    "DENY_DEADLINE",
    "DENY_DUPLICATE",
]


class ToolValidation(_Strict):
    code: ToolValidationCode
    allowed: bool
    proposal: ToolCallProposal | None = None
    resolved_observable_id: str | None = None
    detail_code: str | None = None


def validate_tool_turn(
    proposals: Sequence[ToolCallProposal],
    registry: Mapping[str, Observable],
    visuals: Mapping[str, VisualEvidence],
    lineage: Mapping[str, ObservableLineage],
    history: Sequence[InvestigationStep],
    config: InvestigationConfig,
    context: ToolContext,
    enabled_actions: frozenset[ToolAction],
) -> ToolValidation:
    ...
```

`allowed` MUST equal `code == "ALLOW"`.

In `src/investigator.py` add:

```python
def build_investigator_messages(
    *,
    parsed: ParsedEmail,
    internal: Assessment,
    registry: Mapping[str, Observable],
    evidence: Sequence[Evidence],
    steps: Sequence[InvestigationStep],
    tool_observations: Sequence[dict[str, Any]],
    denial_observations: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    ...


def proposal_from_turn(
    turn: AgentModelTurn,
) -> list[ToolCallProposal]:
    ...


def compute_investigation_deadline(
    *,
    now: float,
    investigation_started: float,
    email_deadline: float,
    config: InvestigationConfig,
) -> float:
    ...
```

Deadline formula is exactly the one in TICKET-19.

In `src/agentic_graph.py`:

```python
def build_agentic_graph(
    services: Services,
    *,
    investigation_config: InvestigationConfig,
    enabled_actions: frozenset[ToolAction] = frozenset(
        {"virustotal", "opencti", "urlscan", "finish_investigation"}
    ),
):
    ...
```

Return the compiled LangGraph object following the same saver/thread conventions as V1.

In `src/agentic_reporting.py`:

```python
def write_investigation_audit(
    *,
    run_dir: Path,
    state: AgenticEmailTriageState,
) -> tuple[Path, Path]:
    ...
```

Returns the written `investigation.json` and `investigation_trace.jsonl` paths.

## STATE / DATA CONTRACTS

Finalize `InvestigationStep` in `src/agentic_state.py` exactly as:

```python
class InvestigationStep(_Strict):
    turn_index: int = Field(ge=1)
    action: ToolAction | None
    observable_id: str | None
    visual_id: str | None
    reason_code: InvestigationReason | None
    validation_code: ToolValidationCode | None
    execution_status: Literal[
        "not_executed",
        "ok",
        "not_found",
        "unavailable",
        "skipped",
        "finish",
        "protocol_error",
    ]
    provider_result_sha256: list[str] = Field(default_factory=list)
    evidence_ids_added: list[str] = Field(default_factory=list)
    observable_ids_added: list[str] = Field(default_factory=list)
    elapsed_ms: FiniteNumber
```

The existing `AgenticEmailTriageState` from T19A remains otherwise unchanged.

Lineage rules:

- parser/email observable → depth 0, origin `email`;
- validated QR observable from T16 → depth 0, origin `qr`;
- derived observable from an allowed ToolResult → parent depth + 1, origin `tool`;
- candidate depth > `max_derived_observable_depth` is not registered.

Deterministic derived observable IDs MUST reuse the existing observable-ID/deterministic-ID helper used by the repository. Do not invent a second ID scheme.

## CONTROL FLOW

Exact graph:

```text
START
→ parse_email
→ internal_assessment
→ complexity_gate

complexity_gate(simple)
→ verify_simple
→ policy_simple
→ write_investigation
→ write_report
→ END

complexity_gate(complex)
→ investigator

investigator
→ validate_tool

validate_tool(ALLOW external tool)
→ execute_tool
→ merge_step_result
→ continue_check

validate_tool(ALLOW finish)
→ finalize_investigation

validate_tool(DENY and denial budget remains)
→ return_denial_to_model
→ continue_check

validate_tool(DENY and denial budget exhausted)
→ finalize_investigation

continue_check(CONTINUE)
→ investigator

continue_check(STOP)
→ finalize_investigation

finalize_investigation
→ merge_final
→ final_assessment
→ verify_final
→ policy_final
→ write_investigation
→ write_report
→ END
```

No transition is implicit.

Node responsibilities:

- `parse_email`: same semantics as V1.
- `internal_assessment`: same INTERNAL call and prompt as V1.
- `complexity_gate`: same `decide_gate()`.
- `investigator`: one `complete_with_tools()` call, increments `agent_turns` once.
- `validate_tool`: pure validation; no network.
- `execute_tool`: dispatch exactly one allowed external action.
- `merge_step_result`: normalize returned ToolResult into existing evidence plus deterministic derived observables/lineage.
- `return_denial_to_model`: append only structured denial data to the in-memory conversation.
- `continue_check`: pure budget/deadline termination check.
- `finalize_investigation`: sets terminal status/reason if not already set.
- `merge_final`, `final_assessment`, `verify_final`, `policy_final`: reuse T09/T10 semantics.
- SIMPLE path uses `internal_copy` semantics and emits zero investigator calls.

## CONFIGURATION / DEFAULT VALUES

T19A values remain unchanged.

Enabled actions in T19B:

```text
virustotal
opencti
urlscan
finish_investigation
```

Compatibility table:

```text
virustotal:
  sha256, url, domain, ipv4, ipv6

opencti:
  sha256, sha1, md5, url, domain, ipv4, ipv6

urlscan:
  url
```

Allowed observable provenance:

```text
INTERNE
OSINT
SANDBOX
```

Never `INFERENCE`.

Allowed roles must intersect:

```text
sender
return_path
reply_to
link_target
transport_ip
attachment
tool_discovery
campaign_id
```

Any observable carrying role `recipient` is denied regardless of other roles.

`displayed_brand` or `shared_host` alone does not authorize a lookup.

## SECURITY INVARIANTS

- Every runtime external call uses `observable_id`.
- Python resolves the current registry object; the model never supplies the raw IOC.
- Existing adapters remain final authority on provider-specific egress rules.
- Tool Validator runs before every adapter invocation.
- A denied call performs zero adapter/network requests.
- No tool result is interpreted as an instruction.
- `not_found` and `unavailable` never become benign evidence.
- No chain-of-thought is persisted.
- No V1 path or V1 adapter is modified.

## IMPLEMENTATION REQUIREMENTS

Tool schemas exposed to the model are exactly:

```text
virustotal(observable_id, reason_code)
opencti(observable_id, reason_code)
urlscan(observable_id, reason_code)
finish_investigation(
    decisive_evidence_ids,
    unresolved_questions,
    stopping_reason
)
```

No other arguments.

`reason_code` must be a member of `InvestigationReason`.

`finish_investigation` accepts only `VoluntaryStopReason`.

Multiple native tool calls in one assistant turn:

- execute zero ;
- create exactly one `DENY_MULTIPLE_CALLS` step ;
- increment `denied_tool_calls` by exactly one ;
- consume the agent turn ;
- return one structured denial observation.

`finish_investigation` consumes an agent turn but is excluded from `executed_tool_calls`.

Budget semantics:

- the first six external executions are permitted subject to all other checks ;
- a proposed seventh external execution is `DENY_BUDGET` ;
- the first two denial events may return to the model ;
- a third denial event ends the investigation with `validator_denial_limit` and executes no tool ;
- a second executed urlscan call is `DENY_BUDGET` ;
- reaching `max_agent_turns` terminates with `max_turns` before an additional model call.

Duplicate definition:

same `action` + same `observable_id` previously executed or previously denied for a permanent validation reason in the current investigation → `DENY_DUPLICATE`.

Do not treat a provider transient error as permission to silently re-query. No identical retry is agent-driven in T19B.

## ERROR HANDLING

`not_found` and `unavailable` are returned verbatim to the agent as structured DATA.

Agent protocol error:

- add one `protocol_error` InvestigationStep ;
- set `investigation_stop_reason="protocol_error"` ;
- proceed to FINAL if INTERNAL assessment exists ;
- do not invent a missing agent conclusion.

If the calculated investigation deadline is already expired, no investigator call is emitted; terminal reason is `deadline`.

## AUDIT / PERSISTENCE

Per run:

- `investigation.json`
- `investigation_trace.jsonl`

`investigation.json` includes at minimum:

- run_id ;
- variant ;
- model ;
- prompt_sha256 ;
- tool_schema_sha256 ;
- gate result ;
- gate reasons ;
- turns ;
- executed_tool_calls ;
- denied_tool_calls ;
- stopping_reason.

Each trace row includes the exact structured audit fields defined in TICKET-19.

No raw email body, raw provider body, image bytes, free-form assistant content or chain-of-thought is written to these files.

## TESTS REQUIRED

Implement exact deterministic tests asserting:

1. SIMPLE → zero investigator call and V1 internal-copy semantics.
2. COMPLEX → investigator called.
3. Unknown observable → `DENY_UNKNOWN_OBSERVABLE`, zero adapter call.
4. Recipient role → `DENY_ROLE`, zero adapter call.
5. INFERENCE provenance → `DENY_PROVENANCE`.
6. URL with userinfo or privacy-invalid target → `DENY_PRIVACY`.
7. Same executed `(action, observable_id)` repeated → `DENY_DUPLICATE`.
8. Two native calls same turn → one `DENY_MULTIPLE_CALLS`, zero execution.
9. Executed call count 6 succeeds when all other conditions pass; seventh denied.
10. Two denied events may recover; third ends with `validator_denial_limit`.
11. Immediate valid finish performs zero external tool call.
12. Tool `not_found` is returned to model and does not create benign evidence.
13. Tool `unavailable` is returned to model and does not create benign evidence.
14. First urlscan may execute; second urlscan execution is denied.
15. Adapter receives the exact registry-resolved Observable, never a model raw string.
16. Genuine ToolResult derived observable receives depth parent+1.
17. Depth 2 is accepted.
18. Candidate depth 3 is discarded and not registered.
19. `src/graph.py` topology/introspection remains unchanged.
20. Existing V1 graph/evidence/verifier/policy tests remain green.
21. Audit files contain no continuation message or assistant free text.
22. Max turns terminates before a ninth investigator response.

## LIVE VALIDATION REQUIRED

G4 already validates V1 adapters and G8-A validates native tool transport.

T19B nevertheless requires one real end-to-end **agentic core smoke** using Qwen and the currently configured approved V1 services.

The smoke is not a benchmark. It must prove:

- INTERNAL executes ;
- a COMPLEX case enters investigator ;
- Qwen proposes one allowed core action or explicit finish ;
- validator decision is recorded ;
- if allowed, existing adapter is used ;
- the result/denial returns to the same investigator loop ;
- the run terminates ;
- FINAL/verifier/policy/reporting complete.

No requirement exists for a specific provider hit/verdict.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_tool_validator.py tests/test_agentic_graph.py tests/test_agentic_reporting.py -q
python -m pytest tests/test_graph.py tests/test_evidence.py tests/test_verify.py tests/test_policy.py -q
python scripts/smoke_agentic.py core --require-configured
python scripts/check_gate.py G8-B --complete-ticket TICKET-19B
python scripts/check_gate.py G8-B --record
python scripts/check_gate.py G8-B
python -m pip check
git diff --check
```

## EXPECTED RESULTS

V1 and V2 coexist in one installation.

Agentic Core uses only existing VT/OpenCTI/urlscan adapters and can terminate without bypassing validation.

## ACCEPTANCE CRITERIA

G8-B PASS.

## FAIL CONDITIONS

- Modification of V1 graph.
- IOC raw string supplied by model to adapter.
- Tool bypass.
- Unbounded loop.
- New provider/network implementation for V1 tools.
- Hidden retry or duplicate call outside the frozen rules.
- V1 regression.

## BLOCKED CONDITIONS

- G8-A not PASS.
- Required V1 adapter absent/incompatible with its ticket contract.

## ARTEFACTS PRODUCED

Agentic Core runtime, validator, V2 graph, audit sidecars and G8-B receipt.

## REGRESSION REQUIREMENTS

Relevant V1 graph/gate/evidence/verifier/policy tests remain green without weakening expectations.

## CODE AGENT EXECUTION PROMPT

Execute only TICKET-19B.

Read AGENTS.md, TICKET-19.md, TICKET-19A.md and this ticket before editing.

Do not modify src/graph.py, src/llm.py, the V1 adapters, the INTERNAL/FINAL prompts, gate config, policy config or scripts/check_gate.py.

Implement the exact V2 graph, validator, contracts, budgets and audit specified here.

Reuse the existing parser, INTERNAL, gate, VT/OpenCTI/urlscan adapters, evidence merge, FINAL, verifier, policy and reporting.

The model may provide only observable IDs, never raw IOC values.

Run every listed command. Stop on any security invariant failure.

Do not implement RAG, vision, QR changes or OSINT+.

Do not start TICKET-19C. Do not push or merge.
