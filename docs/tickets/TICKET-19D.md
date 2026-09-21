# TICKET-19D — Agentic OSINT+

## STATUS / GATE

G8-D

## OBJECTIVE

Ajouter exactement quatre capacités d’investigation structurées à l’agent V2 :

- RDAP ;
- DNS ;
- Certificate Transparency ;
- campaign intelligence.

Aucune autre source OSINT n’est autorisée dans T19-D.

## ARCHITECTURAL AUTHORITY / OVERRIDES

Sources autorisées exclusivement :

- IANA bootstrap + authoritative RDAP servers ;
- Cloudflare DNS-over-HTTPS ;
- SSLMate Cert Spotter API v1 ;
- OpenPhish Community Feed ;
- ThreatFox Community API.

URLhaus est explicitement exclu de T19-D.

Aucun WebSearch, navigateur, scraping libre, WHOIS legacy, passive DNS commercial ou feed supplémentaire.

V09 reste inchangé : aucun nouveau predicate OSINT+ ne devient une confirmation malveillante admissible.

## PRECONDITIONS / DEPENDENCIES

- G8-C PASS and receipt verifies.
- TICKET-19C DONE.
- Operator accepts OpenPhish terms of use before live retrieval.
- `THREATFOX_AUTH_KEY` configured if ThreatFox live validation is required.
- ThreatFox use legally/contractually permitted by the operator.
- Existing T19 tool validator and agentic graph are functioning.
- Read current official provider documentation before implementation; if an endpoint/contract below has become invalid, stop and report BLOCKED rather than silently selecting another provider.

## REUSE FROM PREVIOUS TICKETS

Reuse:

- `ToolContext`
- `ToolResult`
- `ResponseMetadata`
- deterministic ID helper
- evidence merge
- source/provenance validation
- T19 Tool Validator
- T19 agent loop
- existing HTTP/security primitives where compatible
- existing egress/service-approval policy patterns

Do not duplicate V1 adapters or create a generic provider framework.

## MUST NOT MODIFY

- `src/graph.py`
- `src/gate.py`
- `src/policy.py`
- `src/llm.py`
- `src/tools/virustotal.py`
- `src/tools/opencti.py`
- `src/tools/urlscan.py`
- `prompts/internal_assessment.txt`
- `prompts/final_assessment.txt`
- `prompts/investigator.txt`
- `configs/gate.yaml`
- `configs/policy.yaml`
- `scripts/check_gate.py`
- Gold files

V09 semantics MUST NOT change.

## IN SCOPE

Four OSINT+ action families:

1. RDAP ;
2. DNS ;
3. Certificate Transparency ;
4. campaign intelligence implemented by:
   - OpenPhish local snapshot lookup for URL observables ;
   - ThreatFox exact lookup for domain/IPv4/IPv6 observables.

Closed contract extensions for tools/evidence/provenance.

Bounded deterministic derived-observable registration from DNS only.

Provider smokes using benign public test values.

## OUT OF SCOPE

- WebSearch.
- Browser.
- WHOIS legacy port 43.
- Passive DNS commercial services.
- Arbitrary feed ingestion.
- URLhaus.
- URL submission to ThreatFox.
- RDAP/DNS/CT recursive crawling.
- New V09 malicious-confirmation source.
- Model-generated provider query strings.
- Bulk feed crawling beyond the frozen limits.

## FILES ALLOWED

Existing:

- `.env.example`
- `src/config.py`
- `src/state.py`
- `src/prompts.py`
- `src/evidence.py`
- `src/verify.py`
- `src/investigator.py`
- `src/tool_validator.py`
- `src/agentic_graph.py`
- `src/agentic_reporting.py`
- `configs/investigation.yaml`
- `schemas/triage_report.schema.json`
- `scripts/smoke_agentic.py`
- `docs/contracts.md`
- `docs/architecture.md`
- `docs/threat_model.md`

New files listed below.

No other tracked file may be modified.

## NEW FILES

- `src/tools/rdap.py`
- `src/tools/dns.py`
- `src/tools/certspotter.py`
- `src/tools/campaign.py`
- `tests/test_osint_tools.py`
- `tests/test_agentic_osint.py`

## EXISTING INTERFACES REUSED

Each new provider adapter returns the existing `ToolResult` contract after the closed vocabularies defined below are extended.

Reuse existing:

- transport-safe URL construction patterns ;
- response capture/hashing ;
- explicit `ok/not_found/unavailable/skipped` status philosophy ;
- `ToolContext` deadline/egress context ;
- `merge_evidence()` ;
- `verify_assessment()` ;
- `is_admissible_malicious_confirmation()`.

## NEW INTERFACES / EXACT SIGNATURES

`src/tools/rdap.py`:

```python
class RdapAdapter:
    def lookup(
        self,
        query: Observable,
        context: ToolContext,
    ) -> ToolResult:
        ...
```

`src/tools/dns.py`:

```python
class DnsAdapter:
    def lookup(
        self,
        query: Observable,
        context: ToolContext,
    ) -> ToolResult:
        ...
```

`src/tools/certspotter.py`:

```python
class CertSpotterAdapter:
    def lookup(
        self,
        query: Observable,
        context: ToolContext,
    ) -> ToolResult:
        ...
```

`src/tools/campaign.py`:

```python
class CampaignIntelligenceAdapter:
    def lookup(
        self,
        query: Observable,
        context: ToolContext,
    ) -> list[ToolResult]:
        ...
```

Agent-facing actions remain ID-only:

```text
rdap(observable_id, reason_code)
dns(observable_id, reason_code)
certificate_transparency(observable_id, reason_code)
campaign_intelligence(observable_id, reason_code)
```

No raw domain/IP/URL argument exists in any agent-facing schema.

## STATE / DATA CONTRACTS

Extend the existing `ToolResult.tool` closed vocabulary with exactly:

```text
rdap
dns
certificate_transparency
openphish
threatfox
```

Extend `Evidence.source_kind` with exactly the same five values.

Extend producer/provenance mappings so all five map to `OSINT`.

Extend `TOOL_ORDER`, preserving V1 first:

```python
(
    "virustotal",
    "opencti",
    "urlscan",
    "rdap",
    "dns",
    "certificate_transparency",
    "openphish",
    "threatfox",
)
```

Add exactly these `Evidence.predicate` values and no others:

RDAP:

```text
rdap_registration_date
rdap_last_changed_date
rdap_expiration_date
rdap_domain_age_days
rdap_registrar_name
rdap_status
```

DNS:

```text
dns_a
dns_aaaa
dns_mx
dns_ns
dns_cname
```

Certificate Transparency:

```text
ct_certificate_not_before
ct_certificate_not_after
ct_issuer_name
ct_dns_name
ct_certificate_sha256
```

Campaign:

```text
campaign_openphish_exact_url_match
campaign_threatfox_exact_ioc_match
campaign_threat_type
campaign_malware
campaign_tag
campaign_first_seen
campaign_last_seen
campaign_confidence
```

No other new predicate.

All new evidence provenance = `OSINT`.

No new predicate is added to `ADMISSIBLE_CONFIRMATION_PREDICATE`. `sandbox_provider_malicious` remains the malicious-confirmation predicate defined by the existing verifier contract.

DNS may create derived observables. RDAP, CT and campaign tools create evidence only and zero derived observables in T19 V0.

## CONTROL FLOW

No graph topology change from T19B/C.

All OSINT actions use the existing path:

```text
investigator
→ native tool proposal using observable_id
→ Tool Validator
→ registry resolution
→ OSINT adapter
→ normalized ToolResult
→ deterministic evidence merge
→ DNS-only derived-observable extraction if applicable
→ lineage registration
→ investigator
```

Campaign action dispatch is deterministic:

```text
observable.type == url
→ OpenPhish local snapshot only

observable.type in {domain, ipv4, ipv6}
→ ThreatFox only

all other types
→ DENY_INCOMPATIBLE_TYPE
```

A URL is never sent to ThreatFox.

## CONFIGURATION / DEFAULT VALUES

Add closed nested sections to `configs/investigation.yaml`. Unknown fields remain rejected.

### RDAP

```yaml
rdap:
  enabled: true
  bootstrap_scheme: https
  bootstrap_host: data.iana.org
  bootstrap_path: /rdap/dns.json
  timeout_seconds: 8
  max_requests_per_call: 2
```

Behavior:

- one IANA bootstrap GET + one authoritative RDAP GET maximum ;
- bootstrap resolution follows RFC 9224 longest-label match ;
- select the first HTTPS base URL in the matched IANA entry order ;
- only HTTPS ;
- no redirects ;
- any 3xx → `unavailable/api_error` ;
- lookup path follows RDAP domain lookup semantics for the A-label FQDN ;
- only `domain` observables.

### DNS

```yaml
dns:
  enabled: true
  scheme: https
  host: cloudflare-dns.com
  path: /dns-query
  timeout_seconds: 8
  record_types:
    - A
    - AAAA
    - MX
    - NS
    - CNAME
  max_answers_per_type: 5
  max_answers_total: 20
```

HTTP:

- GET ;
- `Accept: application/dns-json`.

Only `domain` observables.

NXDOMAIN → `not_found`.

SERVFAIL/other resolver error → `unavailable/api_error`.

### Certificate Transparency

```yaml
certificate_transparency:
  enabled: true
  scheme: https
  host: api.certspotter.com
  path: /v1/issuances
  timeout_seconds: 8
  max_issuances: 20
  pagination: false
```

Fixed query parameters:

```text
domain=<A-label domain>
include_subdomains=false
match_wildcards=true
expand=dns_names
expand=issuer
```

Use unauthenticated evaluation access only.

Do not claim a fixed unauthenticated hourly quota. It is `UNKNOWN`.

HTTP 429 → `unavailable/rate_limited`.

Only `domain` observables.

### OpenPhish

```yaml
openphish:
  enabled: true
  scheme: https
  host: openphish.com
  path: /feed.txt
  refresh_seconds: 43200
  timeout_seconds: 10
```

One shared feed snapshot per 12-hour window.

Archive snapshot SHA-256 and fetch timestamp.

Exact normalized URL matching is local.

No domain-level inference/match.

No user IOC is transmitted to OpenPhish.

### ThreatFox

```yaml
threatfox:
  enabled: true
  scheme: https
  host: threatfox-api.abuse.ch
  path: /api/v1/
  timeout_seconds: 8
  query: search_ioc
  exact_match: true
  max_records: 10
```

HTTP method: POST.

Auth header: `Auth-Key`.

Add setting:

```python
THREATFOX_AUTH_KEY: SecretStr | None
```

The setting follows existing secret redaction/public-dump rules.

Missing key → `unavailable/not_configured`, zero request.

No URL observable is ever sent to ThreatFox.

## SECURITY INVARIANTS

Tool compatibility:

```text
rdap:
  domain

dns:
  domain

certificate_transparency:
  domain

campaign_intelligence:
  url → OpenPhish local snapshot only
  domain|ipv4|ipv6 → ThreatFox only
```

Every external query value is resolved by Python from an approved registry `observable_id`.

All services pass through:

- Tool Validator ;
- service approval/egress policy ;
- privacy checks ;
- budget ;
- deadline ;
- provider-specific adapter validation.

No full email URL is sent to ThreatFox.

No free-form model query is sent to any provider.

No new OSINT predicate satisfies V09 malicious confirmation.

No provider response text is treated as instruction.

## IMPLEMENTATION REQUIREMENTS

### RDAP normalization

Exact-match validity:

- normalize queried domain to A-label canonical form ;
- response `ldhName` or `unicodeName`, if present, must normalize to the queried domain ;
- mismatch → `unavailable/malformed_response`.

Events:

- `registration` = earliest valid registration event ;
- `last changed` = latest valid last-changed event ;
- `expiration` = latest valid expiration event ;
- `age_days = max(0, floor((collection_utc - registration_utc)/86400))`.

Registrar name is emitted only from the response’s registrant/registrar structure when unambiguously present according to RDAP JSON; no heuristic free-text extraction.

Statuses are normalized as bounded string values already present in the provider response.

### DNS normalization and pivots

Deterministically:

- normalize ;
- deduplicate ;
- sort ;
- cap each RR type to 5 ;
- cap total accepted answers to 20.

Evidence:

- A → `dns_a`
- AAAA → `dns_aaaa`
- MX → `dns_mx`
- NS → `dns_ns`
- CNAME → `dns_cname`

Derived observables:

- A/AAAA → IP observable ;
- MX/NS/CNAME target → domain observable ;
- role exactly `tool_discovery` ;
- provenance exactly `OSINT` ;
- source reference points to the source evidence/result ;
- depth is assigned by the agentic lineage layer, not the DNS adapter.

### Certificate Transparency normalization

- inspect only first response page ;
- accept at most 20 issuance objects ;
- no pagination ;
- issue `ct_certificate_not_before`, `ct_certificate_not_after`, `ct_issuer_name`, `ct_dns_name`, `ct_certificate_sha256` only for values actually present ;
- wildcard/subdomain names are contextual evidence only ;
- zero derived observables.

### OpenPhish normalization

- one exact normalized URL per feed line ;
- ignore blank/invalid lines ;
- lookup is exact URL equality after the repository’s existing safe URL normalization ;
- exact match emits `campaign_openphish_exact_url_match` ;
- no fuzzy/domain/brand similarity ;
- zero derived observables.

### ThreatFox normalization

Request body uses exactly:

```json
{
  "query": "search_ioc",
  "search_term": "<registry-resolved observable>",
  "exact_match": true
}
```

If current official ThreatFox API documentation requires the exact field name `search_term` to differ, T19D is BLOCKED and the ticket specification must be amended before code proceeds. GLM must not improvise.

Accept at most 10 returned records.

Every returned IOC must normalize exactly to the queried domain/IP. Any non-exact returned IOC is ignored and audited as provider mismatch.

Mapped predicates:

- exact hit → `campaign_threatfox_exact_ioc_match`
- threat type → `campaign_threat_type`
- malware → `campaign_malware`
- tags → one `campaign_tag` per bounded returned tag
- first seen → `campaign_first_seen`
- last seen → `campaign_last_seen`
- confidence if supplied → `campaign_confidence`

Zero derived observables.

## ERROR HANDLING

Use existing ToolResult status/reason vocabulary wherever possible.

Minimum mappings:

- missing ThreatFox key → `unavailable/not_configured`
- HTTP 429 → `unavailable/rate_limited`
- timeout → `unavailable/timeout`
- malformed response → `unavailable/malformed_response`
- provider HTTP error → `unavailable/api_error`
- valid empty exact lookup → `not_found`

RDAP 3xx is not followed.

OpenPhish stale-cache behavior:

- if current snapshot age <= 12h, use it ;
- if snapshot is older than 12h, fetch is required ;
- if required fetch fails, return `unavailable/api_error` ;
- never silently present stale feed data as current.

## AUDIT / PERSISTENCE

Raw provider responses follow the repository’s existing restricted response-capture rules.

OpenPhish snapshot additionally records:

- `fetched_at`
- `response_sha256`
- source URL identity

No credential.

For every OSINT call, agent trace records:

- action ;
- observable ID ;
- provider/tool ;
- validator result ;
- execution status ;
- response/result digest ;
- evidence IDs ;
- derived observable IDs ;
- latency ;
- no raw assistant reasoning.

## TESTS REQUIRED

### RDAP

Assert:

1. longest IANA suffix/TLD match.
2. first HTTPS endpoint selected.
3. no HTTP endpoint used.
4. one bootstrap + one authoritative request maximum.
5. response domain exact normalization accepted.
6. mismatched response domain rejected.
7. 3xx refused.
8. malformed response explicit.
9. domain-only compatibility.
10. registration earliest, last-changed latest, expiration latest.
11. non-negative deterministic age days.

### DNS

Assert:

1. A exact normalization.
2. AAAA exact normalization.
3. MX target normalization.
4. NS target normalization.
5. CNAME target normalization.
6. deterministic sort/dedup.
7. max 5 per type.
8. max 20 total.
9. NXDOMAIN → not_found.
10. SERVFAIL → unavailable/api_error.
11. A/AAAA derived IP observable.
12. MX/NS/CNAME derived domain observable.
13. derived role = tool_discovery.
14. depth assigned by lineage layer, not adapter.
15. depth >2 ultimately not registered by agent layer.

### Certificate Transparency

Assert:

1. exact query construction.
2. `include_subdomains=false`.
3. `match_wildcards=true`.
4. both expand values present.
5. first page only.
6. max 20.
7. wildcard/subdomain names are evidence only.
8. no derived observable.
9. 429 explicit.

### Campaign intelligence

Assert:

1. URL exact OpenPhish match.
2. URL no-match.
3. no OpenPhish domain overgeneralization.
4. OpenPhish feed matched locally with zero user-IOC request.
5. stale snapshot refresh behavior.
6. domain ThreatFox exact lookup.
7. IPv4 ThreatFox exact lookup.
8. IPv6 ThreatFox exact lookup.
9. ThreatFox non-exact returned IOC rejected.
10. missing key → zero request.
11. 429 explicit.
12. full URL never sent to ThreatFox.
13. unsupported observable type denied.

### Evidence/verifier

Assert:

1. all five new source kinds map to OSINT.
2. all new predicates accepted only under their correct producer/source.
3. false/impossible source reference rejected by existing verifier semantics.
4. new evidence can be cited by FINAL.
5. none of the new predicates satisfies `is_admissible_malicious_confirmation()`.
6. existing V09 tests remain unchanged and green.

## LIVE VALIDATION REQUIRED

Use only public benign test values defined by the smoke script, not user/customer IOC.

Required live observations:

1. RDAP successful for `example.com` or another IANA-reserved benign domain if the official service requires it.
2. DNS successful for `example.com`.
3. Cert Spotter successful for `example.com`, or explicit documented `rate_limited` limitation if that is the actual real response.
4. OpenPhish Community feed retrieved and hashed.
5. ThreatFox exact no-match/benign-domain query with the real configured Auth-Key.

Do not provoke abuse, malicious submissions or rate limiting.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_osint_tools.py tests/test_agentic_osint.py -q
python -m pytest tests/test_verify.py tests/test_evidence.py -q
python scripts/smoke_agentic.py osint --require-configured
python scripts/check_gate.py G8-D --complete-ticket TICKET-19D
python scripts/check_gate.py G8-D --record
python scripts/check_gate.py G8-D
python -m pytest -q
python -m pip check
git diff --check
```

## EXPECTED RESULTS

OSINT+ is real, normalized, bounded, auditable and usable by the same agent loop without changing V1 semantics.

## ACCEPTANCE CRITERIA

G8-D PASS.

## FAIL CONDITIONS

- New unauthorized source.
- URLhaus integration.
- WebSearch/browser.
- V09 extension.
- Raw provider JSON sent directly to FINAL/investigator as unnormalized evidence.
- Model-generated raw IOC queried.
- URL sent to ThreatFox.
- Provider replaced silently.
- Quota/cap invented as fact.

## BLOCKED CONDITIONS

- G8-C not PASS.
- ThreatFox credential/authorization absent for mandatory live validation.
- OpenPhish terms not operator-approved.
- Official provider endpoint/contract has changed such that this ticket’s frozen interface is no longer valid.
- Mandatory service is unavailable in a way that prevents its required live contract from being observed.

## ARTEFACTS PRODUCED

Four OSINT+ capabilities, normalized evidence, real smoke captures/summaries, OpenPhish snapshot metadata and G8-D receipt.

## REGRESSION REQUIREMENTS

- Existing V1 tool contracts remain compatible.
- Existing V09 semantics unchanged.
- Full non-live suite green.
- `src/graph.py` unchanged.

## CODE AGENT EXECUTION PROMPT

Execute only TICKET-19D.

Read AGENTS.md, TICKET-19.md, TICKET-19A/B/C and this ticket before editing.

Implement exactly IANA/authoritative RDAP, Cloudflare DoH, SSLMate Cert Spotter, OpenPhish Community and ThreatFox as specified.

Do not add another source. Do not add URLhaus. Do not add web search or browser automation.

Keep V09 unchanged.

All external calls must receive a registry-resolved observable after deterministic validation. Never accept a raw IOC value from the model.

Use only the exact new predicates and source kinds defined in this ticket.

Run every validation command.

If ThreatFox authorization, OpenPhish approval or a frozen provider contract is unavailable, report BLOCKED rather than replacing it with another provider/feed.

Do not start TICKET-19E. Do not push or merge.
