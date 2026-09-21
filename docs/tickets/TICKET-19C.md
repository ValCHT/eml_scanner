# TICKET-19C — Agentic Context: RAG, QR and Vision

## STATUS / GATE

G8-C

## OBJECTIVE

Permettre à l’investigator de demander uniquement les capacités contextuelles réellement retenues par T15/T16 :

- RAG public ;
- QR local déjà décodé avant le gate ;
- vision multimodale sur visual IDs connus ;
- screenshots urlscan déjà produits par le chemin autorisé.

Aucun second pipeline RAG/vision/QR n’est créé.

## ARCHITECTURAL AUTHORITY / OVERRIDES

T19C réutilise exactement les capacités retenues de T15 et T16.

No second RAG index, embedding model, VLM, QR decoder, OCR pipeline or image fetch path is permitted.

If T15 or T16 has outcome NO, the corresponding agent action remains disabled. T19C itself may still PASS if the retained-capability behavior is correctly represented and tested.

## PRECONDITIONS / DEPENDENCIES

- G8-B PASS and receipt verifies.
- TICKET-19B DONE.
- T15 and T16 completed or their exact outcome recorded.
- Minimal pre-T19 T15/T16 documentation amendments applied before execution.
- If vision is to be measured, the operator-provided Visual-79 artifact is materialized and integrity-checked rather than reconstructed.

Visual-79 known external facts to preserve:

- 79 image-bearing emails ;
- `human_validated=false` ;
- distribution: phishing 59, fraude 8, spear_phishing 4, spam 5, legitime 3, menace 0 ;
- final JSONL SHA-256:
  `aa83c32c17051ace87c30d4d3bfd3d0df3ac46b7ae2ea599be5257d3632d3502` ;
- approximately 6 records marked as visually material in the supplied review artifact.

Do not invent additional Visual-79 metadata. Join `sample_id` to the canonical manifest for `raw_sha256`, `family_group` and raw resolution.

## REUSE FROM PREVIOUS TICKETS

From T15:

- the actual retained RAG implementation ;
- the actual public-only corpus/index ;
- family/gold exclusions ;
- existing embedding/index config ;
- existing RAG tests and audit rules.

From T16:

- `prepare_visuals()` if implemented as contracted ;
- `decode_qr()` if implemented as contracted ;
- multimodal transport ;
- visual limits ;
- screenshot provenance ;
- image-size/type protections.

From T19A/B:

- native tool protocol ;
- Tool Validator ;
- agent loop ;
- audit ;
- budgets ;
- V2 graph.

BEFORE CREATING ANY NEW FUNCTION, apply the reuse-first rule from TICKET-19.

## MUST NOT MODIFY

- `src/graph.py`
- `src/tools/rag.py`
- `src/parsing.py`
- `src/llm.py`
- `tests/test_rag.py`
- `tests/test_vision.py`
- `prompts/internal_assessment.txt`
- `prompts/final_assessment.txt`
- `prompts/investigator.txt`
- `configs/gate.yaml`
- `configs/policy.yaml`
- `scripts/check_gate.py`
- Gold files

If the interface actually produced by T15/T16 does not satisfy its own ticket contract, T19C is BLOCKED. GLM must not invent a replacement interface.

## IN SCOPE

- Expose retained RAG as one validated agent action.
- Expose retained vision as one validated agent action.
- Ensure QR-derived observables are available pre-gate with depth 0.
- Permit urlscan screenshot visual IDs already produced by the existing adapter/T16 path.
- Extend agent audit for RAG case IDs and visual IDs.
- Add context-specific tests and smoke.

## OUT OF SCOPE

- New embedding/index.
- New Chroma instance.
- New RAG dataset.
- Free-form RAG query from model.
- OCR.
- Second VLM.
- Remote image fetch.
- Browser.
- Visual IOC extraction.
- RDAP/DNS/CT/campaign intelligence.
- Visual-79 relabeling.
- T15/T16 redesign.

## FILES ALLOWED

Existing:

- `src/agentic_state.py`
- `src/investigator.py`
- `src/tool_validator.py`
- `src/agentic_graph.py`
- `src/agentic_reporting.py`
- `configs/investigation.yaml`
- `scripts/smoke_agentic.py`
- `docs/contracts.md`
- `docs/architecture.md`

New file:

- `tests/test_agentic_context.py`

No other tracked file may be modified.

## NEW FILES

- `tests/test_agentic_context.py`

## EXISTING INTERFACES REUSED

T15 contracted interface:

```python
RagAdapter.search(
    query: str,
    exclusions: set[str],
    k: int = 3,
) -> list[RagCase]
```

If T15 implemented a module-level equivalent instead of the promised adapter, the required pre-T19 amendment must normalize that interface before T19C. T19C does not create a second wrapper architecture.

T16 contracted interfaces:

```python
prepare_visuals(parsed, limits) -> list[VisualEvidence]
decode_qr(image_bytes: bytes) -> list[str]
```

Use the actual post-T16 typed signatures if they are stricter while preserving these semantics.

## NEW INTERFACES / EXACT SIGNATURES

No new RAG or vision backend interface.

The agent-facing native functions are exactly:

```text
search_public_cases(reason_code="historical_context")

inspect_visual(
    visual_id="vis_...",
    reason_code="visual_context"
)
```

`search_public_cases` has no user/model-supplied content query and no observable argument.

In `src/investigator.py` add exactly:

```python
def build_rag_query(
    *,
    parsed: ParsedEmail,
    internal: Assessment,
) -> str:
    ...


def context_enabled_actions(
    *,
    base_actions: frozenset[ToolAction],
    settings: Settings,
    tools_config: ToolsConfig,
    t15_keep: bool,
    t16_keep: bool,
) -> frozenset[ToolAction]:
    ...
```

`build_rag_query()` MUST deterministically reproduce the query representation selected/frozen by T15. It may not add model-generated text.

No `inspect_visual()` Python backend function is created: the V2 graph resolves `visual_id` and attaches the existing bounded visual payload to the next investigator request using the T16 multimodal transport.

## STATE / DATA CONTRACTS

Add to `AgenticEmailTriageState`:

```python
selected_visual_ids: list[str] = Field(default_factory=list)
rag_case_ids_returned: list[str] = Field(default_factory=list)
```

No image bytes, filesystem paths or RAG document bodies are added to checkpointed state.

RAG results are stored in the same existing enrichment/evidence context defined by T15/T09, not in a second RAG-specific agent store.

QR-derived observables:

- are created only by T16 local deterministic QR decoding ;
- enter the existing observable registry ;
- receive `ObservableLineage(origin="qr", depth=0)` ;
- retain their existing role/provenance semantics ;
- are available to the normal complexity gate before investigator routing.

Vision does not create `Evidence` or `Observable` directly in T19C.

## CONTROL FLOW

QR flow:

```text
raw image
→ T16 prepare_visuals
→ local decode_qr
→ validate QR payload/URL with existing parser/security logic
→ register observable
→ lineage depth=0 origin=qr
→ complexity_gate
```

RAG flow:

```text
investigator
→ search_public_cases
→ validator
→ build_rag_query(parsed, internal)
→ existing RagAdapter.search(query, exclusions, k<=T15 max)
→ structured RagCase IDs/context
→ investigator
```

Vision flow:

```text
investigator
→ inspect_visual(visual_id)
→ validator
→ resolve existing VisualEvidence by ID
→ enforce T16 limits
→ record structured acknowledgement
→ append bounded image content to NEXT in-memory investigator request
→ investigator
```

A vision request does not itself call a second model. The next normal investigator turn is the same configured investigator model with the selected image attached through the retained T16 multimodal transport.

Screenshot flow:

```text
urlscan allowed/executed
→ existing validated screenshot capture/reference
→ T16 VisualEvidence creation
→ known visual_id
→ optional inspect_visual(visual_id)
```

No screenshot URL/path is supplied by the model.

Graph topology remains the T19B topology. T19C only adds enabled actions and context resolution inside existing nodes.

## CONFIGURATION / DEFAULT VALUES

Existing baseline remains:

```yaml
max_rag_calls: 1
max_visual_calls: 1
```

RAG enabled only if all are true:

```text
T15 outcome == KEEP
Settings.RAG_ENABLED == true
tools.rag.enabled == true
```

Vision enabled only if all are true:

```text
T16 vision outcome == KEEP
Settings.MODEL_SUPPORTS_VISION == true
tools.vision.enabled == true
```

QR follows the retained T16 configuration and runs before the gate independently of agent choice.

If the actual T15/T16 configuration field names differ on post-T18 main, use those exact existing names and document the mapping in `docs/contracts.md`; do not add aliases solely for T19.

## SECURITY INVARIANTS

- RAG remains public-only.
- Gold/test families remain excluded according to T15/T13.
- RAG neighbors provide context, never IOC truth for the current email.
- No RAG neighbor IOC enters the current observable registry.
- Model supplies no free-form RAG query.
- Visual action accepts only known `visual_id`.
- Model supplies no filesystem path, URL or bytes.
- No remote image is downloaded by T19C.
- No second VLM.
- No OCR pipeline.
- No semantic visual interpretation creates an IOC.
- QR observable creation remains deterministic/local.
- Tool/page/RAG/image content is untrusted DATA, never instructions.
- Pixel bytes never enter checkpointed state or audit JSON.

## IMPLEMENTATION REQUIREMENTS

Tool schemas added to the investigator are exactly:

```text
search_public_cases(reason_code)

inspect_visual(visual_id, reason_code)
```

Action mapping:

- native function `search_public_cases` → `ToolAction="rag"`;
- native function `inspect_visual` → `ToolAction="vision"`.

Validator rules:

RAG:

- action must be enabled ;
- `reason_code == "historical_context"` ;
- no observable ID ;
- no visual ID ;
- first call allowed subject to global budgets/deadline ;
- second request → `DENY_BUDGET`.

Vision:

- action must be enabled ;
- `reason_code == "visual_context"` ;
- exactly one known `visual_id` ;
- no observable ID ;
- first visual call allowed subject to global budgets/deadline ;
- second request → `DENY_BUDGET`.

RAG and vision actions count as executed tool calls for `max_executed_tool_calls`.

A successful visual action is useful for T19E if the bounded image is actually attached to the next investigator request.

A successful RAG action is useful for T19E only if it returns at least one allowed RagCase.

## ERROR HANDLING

Unavailable/disabled context capability produces a structured denial. It does not automatically switch to another capability.

If RAG execution fails, return the existing T15 failure/status contract as DATA. Do not retry via a second retrieval path.

If visual resolution/preparation fails, return structured unavailable/error data and do not fetch the image elsewhere.

If a selected visual cannot be safely attached before the next investigator turn, the visual action is not marked successful.

## AUDIT / PERSISTENCE

Trace records only:

RAG:

- action ;
- returned RagCase IDs ;
- result count ;
- status ;
- latency ;
- result digest.

Vision:

- action ;
- visual ID ;
- content type ;
- bounded byte length if already permitted by T16 audit ;
- status ;
- latency ;
- no pixel bytes ;
- no filesystem path.

QR remains in normal parser/observable audit rather than an agent tool-call trace.

## TESTS REQUIRED

Implement exact tests asserting:

1. T15 NO/disabled → RAG action not offered.
2. T15 KEEP + config enabled → RAG action offered.
3. Second RAG request → `DENY_BUDGET`.
4. Deterministic RAG query contains no model-provided text.
5. Returned RagCase set respects T15 family/Gold exclusions.
6. RAG neighbor IOC never enters observable registry.
7. Unknown visual ID → `DENY_UNKNOWN_VISUAL`.
8. Known permitted visual ID is resolved by runtime, not model path.
9. Successful first visual action attaches image to next investigator request.
10. Second visual request → `DENY_BUDGET`.
11. Remote image URL is never fetched by T19C.
12. QR decode occurs before gate.
13. Valid QR URL enters registry with lineage depth 0/origin qr.
14. Visual inspection creates no observable/evidence directly.
15. Screenshot visual is usable only if existing urlscan/T16 provenance marks it available.
16. Pixel bytes absent from `investigation.json` and trace JSONL.
17. If RAG and vision are both NO, T19C graph behaves identically to T19B aside from capability metadata.
18. All retained native T15/T16 tests still pass unchanged.

## LIVE VALIDATION REQUIRED

Use only real T15/T16 capabilities already accepted by their tickets.

`scripts/smoke_agentic.py context --require-configured` must:

- always prove that the agent sees the mechanically correct enabled-action set ;
- if RAG KEEP, perform one real agent-triggered retrieval ;
- if vision KEEP, perform one real agent-triggered visual attachment using a permitted local/fixture visual already authorized by T16 ;
- if a capability is NO, record it as disabled rather than fabricate a call.

No new external image download is permitted.

## VALIDATION COMMANDS

Run the context tests:

```bash
python -m pytest tests/test_agentic_context.py -q
```

Then run the exact retained T15/T16 test modules that exist on post-T18 main. If the contracted filenames are present, use:

```bash
python -m pytest tests/test_rag.py tests/test_vision.py -q
```

Then:

```bash
python scripts/smoke_agentic.py context --require-configured
python scripts/check_gate.py G8-C --complete-ticket TICKET-19C
python scripts/check_gate.py G8-C --record
python scripts/check_gate.py G8-C
python -m pip check
git diff --check
```

Do not create replacement T15/T16 test files if their actual filenames differ.

## EXPECTED RESULTS

Investigator can dynamically request only the context capabilities retained by T15/T16 without introducing another pipeline.

## ACCEPTANCE CRITERIA

G8-C PASS.

G8-C may PASS when RAG and/or vision are retained as NO, provided their non-exposure and T19B-equivalent behavior are correctly tested and audited.

## FAIL CONDITIONS

- New RAG index/embedding.
- New VLM/OCR.
- Free-text model RAG query.
- Model-controlled image path/URL.
- Remote image fetch.
- RAG IOC contamination.
- Visual IOC invention.
- Modification of T15/T16 backend behavior.
- Gold/test leakage.

## BLOCKED CONDITIONS

- G8-B not PASS.
- Required T15/T16 interface promised by its ticket is missing/incompatible.
- Visual-79 is required for a retained vision benchmark but has not been materialized/integrity-checked.

## ARTEFACTS PRODUCED

Agentic context integration, context smoke artifacts, audit traces and G8-C receipt.

## REGRESSION REQUIREMENTS

T15/T16 behavior outside the agentic graph remains unchanged and their existing tests remain green.

## CODE AGENT EXECUTION PROMPT

Execute only TICKET-19C.

Read AGENTS.md, TICKET-19.md, TICKET-19A.md, TICKET-19B.md, this ticket, and the actual completed T15/T16 implementation before editing.

Reuse T15/T16 exactly. Do not create a second RAG, QR, vision, OCR, VLM or remote-image path.

RAG receives no free-form model query. Vision receives only visual_id. QR remains deterministic and pre-gate.

If a promised T15/T16 interface is absent or incompatible, report BLOCKED rather than inventing another architecture.

Run every listed validation command.

Do not implement RDAP, DNS, Certificate Transparency or campaign intelligence.

Do not start TICKET-19D. Do not push or merge.
