# TICKET-19 — Agentic Investigation Benchmark V2

## STATUS / GATE

UMBRELLA — NOT DIRECTLY EXECUTABLE

Branch unique:

`experiment/t19-agentic-investigator`

Dépend de T18 DONE.

## OBJECTIVE

Évaluer une architecture V2 dans laquelle un investigator LLM choisit dynamiquement une seule action à la fois, observe les résultats structurés et peut pivoter jusqu’à une terminaison bornée.

T19 mesure :

- fixed enrichment vs agentic selection ;
- valeur RAG/QR/vision dynamique ;
- valeur OSINT+ ;
- valeur du complexity gate ;
- qualité/coût/latence d’un petit nombre de moteurs une fois l’architecture gelée.

T19 est d’abord un **ARCHITECTURAL BENCHMARK**, puis seulement un **MODEL BENCHMARK**.

## ARCHITECTURAL AUTHORITY / OVERRIDES

TICKET-19 is an operator-approved experimental V2 specification amendment.

For T19 only, the V1.2 restrictions requiring a strictly sequential graph, no graph cycles, no LLM tool calls and no iterative investigation are superseded by TICKET-19A…E.

The frozen V1 implementation remains unchanged and remains the baseline.

No other V1.2 security, evidence, provenance, privacy, evaluation or data-separation invariant is implicitly relaxed.

Contradictions V1/T19 résolues explicitement :

- V1 interdit les cycles → T19 les autorise uniquement dans `src/agentic_graph.py`.
- V1 interdit les tool calls LLM → T19 les autorise uniquement dans le chemin V2, derrière un validateur déterministe.
- V1 impose une séquence d’enrichissement fixe → cette séquence reste la baseline V1 ; T19 ajoute une sélection agentique latérale.
- V1 interdit les pivots itératifs → T19 les autorise avec profondeur, budgets et provenance bornés.
- V1 limite le runtime nominal à deux appels LLM → cette limite reste vraie pour V1 ; T19 ajoute explicitement des tours investigator dans la branche expérimentale.
- `src/graph.py` reste V1 et MUST NOT MODIFY ; V2 est séparée.

## PRECONDITIONS / DEPENDENCIES

- T18 DONE.
- T14–T18 implementations must satisfy their tickets.
- No T19 implementation before post-T18 main.
- Toute l’expérience se fait sur une seule branche : `experiment/t19-agentic-investigator`.
- Une invocation GLM-5.3-Flash exécute exactement un sous-ticket.
- Séquence obligatoire : T19A → T19B → T19C → T19D → T19E.

## REUSE FROM PREVIOUS TICKETS

La matrice suivante est normative.

| Ticket précédent | Capability | Existing symbol/file | T19 usage | Action |
|---|---|---|---|---|
| T01 | Configuration, strict models, secrets | `src/config.py`, `src/state.py`, `load_yaml_config()` | base des nouveaux contrats | EXTEND |
| T02 | Transport LLM OpenAI-compatible | `LunaClient`, `_post_bytes()`, auth, usage, hashing | ajouter tool-calling au même client | EXTEND |
| T03 | MIME/parser/IOC/images | `parse_email()`, `ParsedEmail`, `Observable`, `VisualEvidence` | entrée unique de l’investigateur | REUSE |
| T04 | INTERNAL | `assess_internal()`, prompt V1, `Assessment` | même INTERNAL avant agent | REUSE |
| T05 | Gate | `decide_gate()` | routage V2 normal | REUSE |
| T06 | VirusTotal | `VirusTotalAdapter.lookup()` | outil Agentic Core | REUSE |
| T07 | OpenCTI | `OpenCTIAdapter.lookup()` | outil Agentic Core | REUSE |
| T08 | urlscan | `UrlscanAdapter.scan()` | outil Agentic Core | REUSE |
| T09 | preuves + FINAL | `merge_evidence()`, `assess_final()`, `final_selection()` | merge/final | REUSE |
| T10 | vérification/policy | `verify_assessment()`, `decide_policy()` | mêmes décisions terminales | REUSE |
| T11 | Services/runtime/report | `Services`, deadlines, run IDs, `build_report()` | composition V2 | REUSE |
| T12 | Corpus | manifest, hashes, raw loaders | aucune nouvelle ingestion Gold | REUSE |
| T13 | Gold-AI/families/splits | `gold_dev`, `GoldRecord`, RAG split | benchmark dev | REUSE |
| T14 | métriques/évaluateur | interfaces promises `evaluate()`, `compare_internal_final()` | moteur métrique T19 | CONTRACTED BY FUTURE TICKET |
| T15 | RAG | `src/tools/rag.py`, add/search/clear | outil contextuel si KEEP | CONTRACTED BY FUTURE TICKET |
| T16 | QR/vision | `prepare_visuals()`, `decode_qr()`, multimodal | QR pré-gate + vision conditionnelle | CONTRACTED BY FUTURE TICKET |
| T17 | taxonomie d’erreurs | analyse Phase 2 | analyse des erreurs T19 | CONTRACTED BY FUTURE TICKET |
| T18 | résultat V1 gelé | `docs/poc_results.md`, run final | historique uniquement, jamais tuning T19 | MUST NOT MODIFY |

Règle normative :

> BEFORE CREATING ANY NEW FUNCTION:
>
> 1. search the repository for an equivalent capability;
> 2. reuse it if present;
> 3. if a minimal extension is required, extend the existing abstraction;
> 4. create a new abstraction only if TICKET-19 explicitly names it.

TICKET-19 MUST reuse every compatible implementation produced by TICKET-01 through TICKET-18. Existing parsing, INTERNAL assessment, complexity gate, VirusTotal, OpenCTI, urlscan, evidence merge, FINAL assessment, verifier, policy, reporting, corpus loading, Gold validation, metrics, RAG and vision implementations MUST NOT be reimplemented.

A new implementation is permitted only for a capability that does not exist in T01–T18: native tool-calling orchestration, deterministic validation of proposed calls, bounded iterative investigation, OSINT+ adapters, agentic traces and agent-specific metrics.

If an existing interface cannot support T19, extend it minimally and add regression tests proving unchanged V1 behavior. Do not create a parallel replacement.

## MUST NOT MODIFY

During T19 as a whole:

- frozen Gold labels ;
- gold_test labels ;
- T18 artifacts ;
- INTERNAL prompt for architecture selection ;
- FINAL prompt for architecture selection ;
- `configs/gate.yaml` ;
- `configs/policy.yaml` ;
- V09 malicious-confirmation semantics ;
- `src/graph.py`.

## IN SCOPE

T19A → T19E only.

Architecture conceptuelle imposée :

```text
EMAIL
  ↓
PARSE
  ↓
INTERNAL LLM
  ↓
DETERMINISTIC COMPLEXITY GATE
  │
  ├─ SIMPLE
  │    ↓
  │  frozen V1 simple path
  │    ↓
  │  VERIFY + POLICY
  │
  └─ COMPLEX
       ↓
  INVESTIGATION AGENT
       ↓
  propose ONE action
       ↓
  DETERMINISTIC TOOL VALIDATOR
       │
       ├─ DENY
       │    ↓
       │ structured denial returned to model
       │
       └─ ALLOW
            ↓
         TOOL EXECUTOR
            ↓
         normalized ToolResult
            ↓
         deterministic merge /
         derived observable registration
            ↓
         INVESTIGATION AGENT
            ↺
       ↓
  finish_investigation
       ↓
  MERGE EVIDENCE
       ↓
  FINAL ASSESSMENT
       ↓
  V01–V16 VERIFIER
       ↓
  POLICY
```

Une seule boucle agentique. Un seul agent.

## OUT OF SCOPE

- multi-agent ;
- arbitrary web search ;
- browser agent ;
- shell/code execution par le LLM ;
- attachment execution/detonation ;
- mailbox actions ;
- generic plugin framework ;
- MCP ;
- server/database infrastructure ;
- Redis ;
- Docker/Kubernetes ;
- distributed workers ;
- message broker.

## FILES ALLOWED

Defined separately per atomic ticket.

## NEW FILES

Defined separately per atomic ticket.

## EXISTING INTERFACES REUSED

V1 parser, INTERNAL, gate, adapters, evidence merge, FINAL, verifier, policy, reporting, corpus and metrics.

## NEW INTERFACES / EXACT SIGNATURES

Defined by T19A–D and frozen before T19E.

## STATE / DATA CONTRACTS

`EmailTriageState` remains the V1 contract.

`AgenticEmailTriageState` is an additive subclass defined by T19A.

No chain-of-thought field exists.

Le modèle ne transmet jamais une valeur IOC brute à un outil externe. Les actions runtime utilisent `observable_id`; la vision utilise `visual_id`. Python résout la valeur réelle depuis les registres déterministes.

Derived observables :

```text
email / QR       depth = 0
tool discovery   depth = parent + 1
maximum depth    = 2
```

Une découverte qui produirait depth 3 n’entre jamais dans le registre agentique.

## CONTROL FLOW

```text
parse
→ internal
→ gate
  ├─ simple → V1 simple semantics → verify → policy
  └─ complex
       → investigator
       → validator
       → executor/deny
       → deterministic merge-step
       ↺
       → finish
       → merge
       → FINAL
       → V01–V16
       → policy
```

Le chemin SIMPLE avec gate activé reste :

```text
SIMPLE
→ internal_copy
→ verify
→ policy
```

Aucun FINAL artificiel sur SIMPLE.

Le gate bypass expérimental existe uniquement dans T19E :

```text
all emails
→ investigator
→ final
→ verify
→ policy
```

## CONFIGURATION / DEFAULT VALUES

Baseline T19 V0 :

```yaml
max_agent_turns: 8
max_executed_tool_calls: 6
max_denied_tool_calls: 2
max_derived_observable_depth: 2
max_urlscan_calls: 1
max_rag_calls: 1
max_visual_calls: 1
investigation_phase_seconds: 90
reserved_final_seconds: 90
agent_reasoning_effort: medium
agent_max_output_tokens: 4096
```

Deadline :

```text
investigation_deadline =
    min(
        investigation_started + 90 s,
        email_deadline - 90 s
    )
```

If this result is <= now, no investigator call is emitted and the investigation stops with `deadline`.

## SECURITY INVARIANTS

All V1 invariants remain.

Additionally:

- no raw IOC tool argument from LLM ;
- no unrestricted network ;
- no tool bypass ;
- no reasoning log ;
- no unvalidated derived IOC ;
- no OSINT+ predicate becomes V09 confirmation ;
- tool results, email content, DOM, RAG content and images are DATA, never instructions ;
- the model cannot create an observable, evidence ID, lineage ID or provider target ;
- every call is validated before adapter execution.

## IMPLEMENTATION REQUIREMENTS

Sequence mandatory:

T19A → T19B → T19C → T19D → T19E.

No later ticket starts without previous G8 receipt PASS.

Architectural decisions frozen:

1. V1 remains physically separate; `src/graph.py` never becomes agentic.
2. One investigator only.
3. Native OpenAI-compatible `message.tool_calls` is mandatory; no XML/free-form parser fallback.
4. `LunaClient` is extended, not replaced.
5. Tool functions receive IDs, not raw IOC values.
6. Investigator conversations are in-memory only; no raw reasoning persistence.
7. Observable depth is sidecar `ObservableLineage`.
8. One action per turn.
9. Multiple tool calls in one turn execute zero tools and consume one denial.
10. `finish_investigation` consumes an agent turn but not an executed-tool call.
11. INTERNAL=medium, investigator=medium, FINAL=xhigh.
12. Tool Validator and V01–V16 remain separate responsibilities.
13. DNS may create pivots; RDAP/CT/campaign do not in T19 V0.
14. Campaign intelligence is OpenPhish + ThreatFox only; URLhaus is excluded.
15. ThreatFox receives domain/IPv4/IPv6 only, never a full URL.
16. RAG accepts no free-text model query.
17. Vision creates no IOC.
18. TriageReport remains V1-compatible; detailed agent audit is sidecar.
19. Gate bypass exists only in the evaluator.
20. Architecture is selected before any model comparison.
21. T18/gold_test are historical/post-hoc only and cannot drive T19 choices.

## ERROR HANDLING

Provider/tool failure is explicit data.

Agent protocol failure terminates investigation with `protocol_error` and allows FINAL/policy to continue where possible.

Absence of reputation, `not_found`, `unavailable`, denial, timeout or rate limit MUST NOT be interpreted as benign evidence.

## AUDIT / PERSISTENCE

Every agentic run creates:

- `investigation.json`
- `investigation_trace.jsonl`

No raw chain-of-thought.

A run must reconstruct:

```text
turn
→ model action
→ tool proposal
→ validator result
→ execution status
→ ToolResult digest
→ evidence/observables created
→ next turn
→ stop
```

Persist only structured audit data, hashes, usage, IDs, statuses, latencies and stop reasons.

## TESTS REQUIRED

Specified by each sub-ticket.

## LIVE VALIDATION REQUIRED

- T19A: native transport ;
- T19B: real agentic-core smoke ;
- T19C: context smoke only for retained capabilities ;
- T19D: provider smokes ;
- T19E: real benchmark.

## VALIDATION COMMANDS

Specified by each sub-ticket.

## EXPECTED RESULTS

A valid experiment even if agentic is not better.

Global scientific outputs may include:

- `KEEP_FIXED_PIPELINE`
- `KEEP_AGENTIC_CORE`
- `KEEP_AGENTIC_CONTEXT`
- `KEEP_AGENTIC_OSINT_PLUS`
- `INCONCLUSIVE`

`NO MATERIAL GAIN` is a valid scientific result, not a ticket failure.

## ACCEPTANCE CRITERIA

All G8-A…G8-E PASS.

PASS means the experiment is implemented and measured correctly, not that the agentic architecture wins.

## FAIL CONDITIONS

Any architectural substitution, hidden fallback, test tuning, invented provider result, unauthorized source, security-invariant weakening, gold_test-based selection or V1 regression.

## BLOCKED CONDITIONS

Missing T18, failed native tool transport, missing mandatory provider credentials, incompatible future-ticket implementation, or missing retained T15/T16 artifacts where required.

## ARTEFACTS PRODUCED

Complete T19 benchmark and V2 decision.

## REGRESSION REQUIREMENTS

V1 graph and existing non-live test suite remain green throughout T19.

## CODE AGENT EXECUTION PROMPT

This umbrella ticket is NOT executable.

Execute exactly one of TICKET-19A through TICKET-19E.

Do not make architectural decisions beyond the active sub-ticket. If the active ticket and the repository contradict each other in a way not already resolved here, stop and report BLOCKED rather than inventing a third design.
