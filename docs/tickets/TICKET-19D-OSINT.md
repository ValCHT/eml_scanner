# TICKET-19D-OSINT — OSINT+ minimal et profils agentiques (v2.1)

> NOTE U1 (TICKET-19D-OSINT-U1, `IMPLEMENTED_OSINT_VERIFIER_UNBLOCKED`) :
> correction de spec uniquement — `dnspython==2.9.0` (pin invalide, version
> inexistante sur PyPI au 2026-09-22, dernière réelle `2.8.0`) est remplacé
> par `dnspython==2.8.0` aux §10 et §OPENCODE. PSL inchangée :
> `publicsuffixlist==1.0.2.20260921`. Les manifests de dépendances
> (`pyproject.toml`, `requirements.lock`) ne sont PAS modifiés par U1 ; les
> dépendances seront ajoutées lorsque T19D-OSINT reprendra (préconditions de
> reprise : verifier `compatible_not_confirming`, pin DNS `2.8.0`).

## STATUT

IMPLEMENTED_OSINT_PROFILES_VALIDATED

## CLÔTURE

Validation finale au 2026-09-22 :

- ThreatFox live PASS sur `example.com` et `1.1.1.1` : vrais POST HTTP, résultats `not_found` ;
- RDAP live PASS ;
- DNS live PASS ;
- Certificate Transparency : `external_unavailable` sur le run final, best-effort et non bloquant, avec tests offline PASS ;
- `secret_persisted=false` ;
- verifier : `compatible_not_confirming` ; V09 inchangé ;
- `schemas/assessment.schema.json` inchangé ;
- hash tools `agentic_core` / `agentic_context` inchangé depuis T19D ;
- `max_tool_calls=4` inchangé ;
- tests ciblés post-review : 368 PASS ;
- full pytest post-review : 895 PASS / 27 deselected ;
- `pip check` PASS ;
- `git diff --check` PASS ;
- `gold_test` fermé ;
- Visual-79 non exécuté ;
- aucun benchmark complet ;
- T19E non commencé.

Le ticket est clos. Aucun tuning supplémentaire avant T19E.

## GATE

Aucune nouvelle gate.

Ce ticket est une extension pré-T19E.

Il ne lance aucun benchmark.

---

# CHANGELOG v2.1

Par rapport à la v2 :

1. PSL figée définitivement :
   `publicsuffixlist==1.0.2.20260921`.
2. Suppression du faux besoin d'« ajouter OSINT » à la provenance :
   `OSINT` existe déjà dans le contrat partagé actuel ; on le vérifie mais
   on ne le modifie pas.
3. `effective_capabilities` décrit les capacités ACTIVES pour le run,
   pas le fait que Qwen ait réellement utilisé un tool ou qu'une source ait
   retourné un résultat.
4. crt.sh reste best-effort :
   une indisponibilité externe réelle n'invalide pas toute l'implémentation
   si l'egress réel a été tenté et que les tests offline sont verts.
5. Méthode PSL explicitée :
   `PublicSuffixList().privatesuffix(...)`.
6. Aucun autre changement architectural par rapport à la v2.

---

# 0. RÔLE DU TICKET

Ajouter quatre sources OSINT publiques au runtime agentique :

- ThreatFox / abuse.ch ;
- RDAP ;
- DNS ;
- Certificate Transparency via crt.sh ;

et ajouter exactement quatre profils :

- `agentic_core`
- `agentic_context`
- `agentic_osint`
- `agentic_full`

Principe directeur :

> Ajouter le minimum nécessaire pour comparer
> Core / Context / OSINT / Full à T19E.
>
> Pas de framework.
> Pas de plugin manager.
> Pas de nouvel agent.
> Pas de sur-ingénierie.

---

## 0.1 Périmètre des sources — décision figée

OpenPhish et URLhaus sont HORS PÉRIMÈTRE de ce ticket.

Raison :

ce sont principalement des sources centrées sur les URLs.

Ce ticket n'envoie volontairement aucune URL issue d'un email aux nouveaux
fournisseurs OSINT+.

Les URLs restent couvertes par :

- VirusTotal ;
- urlscan.

ThreatFox est conservé uniquement pour :

- domaines ;
- IPv4 / IPv6 ;
- MD5 ;
- SHA-256.

ThreatFox est principalement orienté malware / C2.

Cette limitation devra être rappelée pendant l'interprétation de T19E.

---

## 0.2 Numérotation

Ajouter dans `docs/gates.md` :

| Document de référence | Ticket réel |
|---|---|
| T19C « Agentic Context » | TICKET-19D / merge `5af9a18` |
| T19D « OSINT+ » | TICKET-19D-OSINT |
| T19E | inchangé |

---

# 1. PRÉCONDITIONS

## 1.1 Base Git

Commencer uniquement depuis un `main` propre contenant le merge T19D :

```text
5af9a189080fd40be6ab8ad9e21452d4b1ff2b30
```

Exécuter :

```bash
git fetch origin
git checkout main
git pull --ff-only
git status
git rev-parse HEAD
```

Conditions :

- arbre tracked propre ;
- HEAD = `5af9a18...` ou descendant ;
- T19D présent.

Sinon :

```text
BLOCKED
```

Ne jamais reprendre directement la branche T19D.

Créer une nouvelle branche/worktree.

---

## 1.2 Vérification des contrats existants

AVANT tout changement de code, vérifier :

### A. Provenance partagée

Le contrat actuel doit déjà autoriser :

```text
OSINT
```

dans le type partagé `Provenance`.

État attendu du repository actuel :

```python
Provenance = Literal[
    "INTERNE",
    "OSINT",
    "SANDBOX",
    "INFERENCE",
]
```

Si `OSINT` est déjà présent :

```text
NE PAS MODIFIER ce Literal.
```

S'il est absent :

```text
BLOCKED_CONTRACT_OSINT_PROVENANCE_MISSING
```

Ne pas décider soi-même de modifier ce contrat.

### B. Assessment schema

Vérifier que :

```text
schemas/assessment.schema.json
```

n'énumère PAS les `source_kind` ou provenances des Evidence externes.

Si son extension serait nécessaire pour accepter les nouvelles evidences :

```text
BLOCKED_ASSESSMENT_SCHEMA_ENUMERATES_PROVENANCE
```

Le schema Assessment ne doit pas changer dans ce ticket.

---

## 1.3 Public Suffix List — VERSION FIGÉE

Version imposée :

```text
publicsuffixlist==1.0.2.20260921
```

Aucune décision de version n'est laissée au coding agent.

Utiliser :

```python
from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList()
registrable_domain = psl.privatesuffix(normalized_domain)
```

Interdit :

```text
update()
download
fetch PSL
HTTP PSL
fichier PSL téléchargé au runtime
```

La liste embarquée dans le package est utilisée.

La version exacte :

```text
1.0.2.20260921
```

est archivée dans le runtime contract lorsque OSINT est actif.

---

# 2. ARCHITECTURE CIBLE

```text
email
  ↓
parser
  ↓
RAG / QR / Vision selon profil
  ↓
UN SEUL agent Qwen3.8
  ↓
lookup_virustotal
lookup_opencti
scan_urlscan
lookup_osint          ← UN SEUL nouveau tool
finalize_assessment
  ↓
merge_evidence
  ↓
verify_assessment
  ↓
decide_policy
```

Il reste exactement :

```text
1 agent
1 boucle Python bornée
1 modèle
0 planner
0 critic
0 judge
0 MCP
0 browser
0 shell
0 mémoire persistante
```

---

# 3. DÉCISION ARCHITECTURALE FIGÉE

NE PAS créer :

```text
lookup_rdap
lookup_dns
lookup_ct
lookup_threatfox
```

Créer uniquement :

```text
lookup_osint
```

Schema LLM exact :

```json
{
  "type": "function",
  "function": {
    "name": "lookup_osint",
    "description": "Enrich an existing domain, public IP or supported hash with bounded public OSINT. The backend selects applicable sources. Absence of results never proves benignity.",
    "parameters": {
      "type": "object",
      "properties": {
        "observable_id": {
          "type": "string"
        }
      },
      "required": [
        "observable_id"
      ],
      "additionalProperties": false
    }
  }
}
```

Le modèle choisit uniquement :

```text
observable_id
```

Il ne choisit jamais :

```text
provider
hostname
URL API
type DNS
query ThreatFox
query RDAP
query CT
domaine enregistrable
```

---

# 4. TYPES SUPPORTÉS ET ROUTAGE

`lookup_osint` accepte uniquement un `observable_id` déjà présent dans le
registre de l'email courant.

## domain

Ordre exact :

| # | Source | Cible |
|---|---|---|
| 1 | ThreatFox | hostname normalisé exact |
| 2 | RDAP | domaine enregistrable |
| 3 | DNS | hostname normalisé exact |
| 4 | Certificate Transparency | domaine enregistrable |

Si aucun domaine enregistrable n'existe :

```text
RDAP → skipped / no_registrable_domain / requests_sent=0
CT   → skipped / no_registrable_domain / requests_sent=0
```

ThreatFox et DNS continuent normalement.

## ipv4 / ipv6

```text
1. ThreatFox
2. RDAP
```

## md5 / sha256

```text
1. ThreatFox
```

## url

```text
skipped
reason=not_applicable
requests_sent=0
```

Aucune URL n'est envoyée aux nouvelles sources.

Une URL n'est PAS automatiquement convertie en domaine.

Si son domaine existe déjà comme Observable séparé, Qwen peut demander
`lookup_osint` sur CET observable domain.

## sha1 / email / message_id / campaign_id

```text
skipped
reason=not_applicable
requests_sent=0
```

Aucune substitution.

---

# 5. NORMALISATION DES TARGETS

## 5.1 Domaine

Ordre exact :

1. `strip()`;
2. lowercase ;
3. suppression du `.` final ;
4. conversion IDN :

```python
value.encode("idna").decode("ascii")
```

5. si conversion impossible :

```text
skipped
reason=invalid_observable
requests_sent=0
```

6. refus local de :

```text
localhost
*.localhost
*.test
*.invalid
*.local
*.example
*.internal
*.corp
*.home.arpa
```

Résultat :

```text
skipped
reason=invalid_observable
requests_sent=0
```

Attention :

```text
example.com
```

est autorisé.

`.example` est refusé.

---

## 5.2 Domaine enregistrable

Utiliser exactement :

```python
from publicsuffixlist import PublicSuffixList

psl = PublicSuffixList()
registrable_domain = psl.privatesuffix(normalized_domain)
```

Aucun téléchargement PSL.

Tests obligatoires notamment :

```text
www.example.co.uk → example.co.uk
foo.blogspot.com  → foo.blogspot.com
```

et au moins un suffixe de plateforme privée réellement présent dans la PSL
embarquée.

Si :

```python
registrable_domain is None
```

alors :

```text
RDAP → skipped/no_registrable_domain
CT   → skipped/no_registrable_domain
```

La cible exacte utilisée par chaque source doit apparaître dans :

```text
query_target
```

du bundle OSINT.

---

## 5.3 IP

Utiliser :

```python
ipaddress.ip_address(value)
```

Autoriser uniquement :

```python
address.is_global is True
```

Sinon :

```text
skipped
reason=non_global_ip
requests_sent=0
```

Utiliser :

```python
address.compressed
```

comme valeur normalisée.

---

## 5.4 Hashes

MD5 :

```text
exactement 32 caractères hex
```

SHA-256 :

```text
exactement 64 caractères hex
```

Normalisation :

```text
lowercase
```

Sinon :

```text
skipped
reason=invalid_observable
requests_sent=0
```

---

# 6. CONTRAT NORMALISÉ

Un appel `lookup_osint` retourne exactement :

```python
ToolResult(
    tool="osint",
    ...
)
```

UN seul ToolResult.

Pas un ToolResult par fournisseur.

Les Evidence OSINT utilisent :

```text
provenance = OSINT
source_kind = osint
```

Le fournisseur réel est porté par :

```text
source_group
```

Valeurs autorisées :

```text
threatfox
rdap
dns
certificate_transparency
```

Invariant conservé :

```text
Evidence.source_kind == ToolResult.tool
```

Donc :

```text
ToolResult.tool = "osint"
Evidence.source_kind = "osint"
```

Ne pas réarchitecturer `merge_evidence`.

---

# 7. EXTENSION MINIMALE DES CONTRATS

Dans :

```text
src/state.py
```

modifier uniquement ce qui suit.

## ToolResult.tool

Ajouter :

```text
osint
```

## Evidence.source_kind

Ajouter :

```text
osint
```

## Evidence.provenance

`OSINT` existe déjà dans le type partagé actuel.

Donc :

```text
NE PAS modifier Provenance si OSINT est déjà présent.
```

La seule modification nécessaire est que les nouvelles Evidence utilisent ce
type existant.

## Evidence.predicate

Ajouter exactement :

```text
osint_threatfox_match
osint_threatfox_threat_type
osint_threatfox_malware
osint_threatfox_confidence
osint_threatfox_first_seen
osint_threatfox_last_seen

osint_rdap_registration_date
osint_rdap_expiration_date
osint_rdap_last_changed
osint_rdap_registrar
osint_rdap_status
osint_rdap_nameserver

osint_dns_a
osint_dns_aaaa
osint_dns_mx
osint_dns_ns
osint_dns_txt

osint_ct_certificate_count
osint_ct_first_not_before
osint_ct_last_not_before
osint_ct_dns_name
```

Aucun autre predicate.

Mettre :

```text
schemas/triage_report.schema.json
```

en cohérence avec :

```text
src/state.py
```

NE PAS modifier :

```text
schemas/assessment.schema.json
```

Hash attendu inchangé :

```text
eeb646dcff9c1514c7e01cefcd900437bc372ecb9696c087b4878692c37021a2
```

---

# 8. MERGE EVIDENCE

Dans :

```text
src/evidence.py
```

ajouter :

```python
PROVENANCE_BY_SOURCE_KIND["osint"] = "OSINT"
```

et permettre :

```text
ToolResult(tool="osint")
```

Conserver tous les invariants existants :

```text
non-ok result
→ aucune evidence positive

ok result
→ response_ref obligatoire
→ response_sha256 obligatoire

Evidence positive
→ source_ref obligatoire
→ observed_at obligatoire
```

Pour OSINT :

```python
ToolResult.observables = []
```

TOUJOURS.

Aucun :

```text
pivot
récursion
subdomain crawling
tool-discovered observable
```

---

# 9. ADAPTATEUR UNIQUE

Créer :

```text
src/tools/osint.py
```

Un seul adaptateur public :

```python
class OsintAdapter:
    def lookup(
        self,
        query: Observable,
        context: ToolContext,
    ) -> ToolResult:
        ...
```

Fonctions internes simples :

```text
_normalize_target(...)
_registrable_domain(...)
_lookup_threatfox(...)
_lookup_rdap(...)
_lookup_dns(...)
_lookup_ct(...)
```

Pas de classe publique supplémentaire.

Pas de framework d'adapters.

Pas de nouveau client HTTP générique.

HTTP :

```text
urllib.request
```

DNS :

```text
dnspython
```

PSL :

```text
publicsuffixlist
```

---

# 10. DÉPENDANCES

Ajouter exactement :

```text
dnspython==2.8.0
publicsuffixlist==1.0.2.20260921
```

(U1 : pin DNS corrigé — `2.9.0` n'existe pas sur PyPI ; dernière réelle
`2.8.0` au 2026-09-22.)

Mettre à jour :

```text
pyproject.toml
requirements.lock
```

Ne mettre à jour aucune dépendance sans rapport.

Aucun téléchargement PSL runtime.

---

# 11. CONFIGURATION

Ajouter dans :

```text
configs/tools.yaml
```

exactement :

```yaml
osint:
  enabled: true
  phase_timeout_s: 40
  threatfox_timeout_s: 10
  rdap_timeout_s: 10
  dns_timeout_s: 5
  ct_timeout_s: 10
  max_ct_response_bytes: 2097152
  max_ct_names: 20
  max_dns_values_per_type: 10
```

Dans :

```text
src/config.py
```

créer :

```python
class OsintToolConfig(_YamlStrict):
    enabled: bool
    phase_timeout_s: float = Field(gt=0)
    threatfox_timeout_s: float = Field(gt=0)
    rdap_timeout_s: float = Field(gt=0)
    dns_timeout_s: float = Field(gt=0)
    ct_timeout_s: float = Field(gt=0)
    max_ct_response_bytes: int = Field(gt=0)
    max_ct_names: int = Field(gt=0)
    max_dns_values_per_type: int = Field(gt=0)
```

et ajouter :

```python
osint: OsintToolConfig
```

à `ToolsConfig`.

Aucune autre config OSINT.

---

# 12. SECRET THREATFOX

Ajouter :

```python
ABUSECH_API_KEY: SecretStr | None = None
```

dans `Settings`.

Ajouter :

```text
ABUSECH_API_KEY
```

à `_SECRET_FIELDS`.

Le code applicatif connaît uniquement :

```text
ABUSECH_API_KEY
```

Il ne connaît PAS :

```text
macOS Keychain
abusech-api-key
security find-generic-password
```

Aucune clé dans :

```text
config
manifest
trace
capture
report
tests
fixtures
git
```

`public_dump()` :

```text
ABUSECH_API_KEY = null
```

`secret_presence()` :

```text
ABUSECH_API_KEY = true|false
```

uniquement.

---

# 13. THREATFOX

Endpoint fixe :

```text
https://threatfox-api.abuse.ch/api/v1/
```

Méthode :

```text
POST
```

Headers :

```text
Auth-Key: <ABUSECH_API_KEY>
Content-Type: application/json
```

Ne jamais archiver les request headers.

## domain / ipv4 / ipv6

Body exact :

```json
{
  "query": "search_ioc",
  "search_term": "<normalized value>",
  "exact_match": true
}
```

## md5 / sha256

Body exact :

```json
{
  "query": "search_hash",
  "hash": "<normalized hash>"
}
```

Interdit :

```text
submit_ioc
get_iocs
taginfo
malwareinfo
wildcard
exact_match=false
```

ThreatFox est :

```text
READ ONLY
```

Maximum :

```text
1 requête HTTP par lookup_osint
```

Pas de retry.

---

# 14. THREATFOX — PROJECTION

Si clé absente :

```text
status=unavailable
reason=not_configured
requests_sent=0
```

Puis continuer les autres sources applicables.

Réponse positive :

maximum :

```text
5 résultats
```

dans l'ordre fournisseur.

Créer uniquement les evidences disponibles parmi :

```text
osint_threatfox_match
osint_threatfox_threat_type
osint_threatfox_malware
osint_threatfox_confidence
osint_threatfox_first_seen
osint_threatfox_last_seen
```

Toujours :

```text
source_group=threatfox
```

Ne jamais transmettre au modèle :

```text
reporter
comment
reference URL
tags complets
malware aliases
malpedia URL
```

`not_found` :

```text
aucune Evidence positive
```

---

# 15. RDAP

Bootstrap :

```text
https://rdap.org
```

Paths :

```text
/domain/<registrable_domain>
/ip/<ip>
```

Interdit :

```text
entity
autnum
search
WHOIS
```

## Redirect

Autoriser maximum :

```text
1 redirect
```

vers le serveur RDAP autoritatif (donc maximum 2 requêtes HTTP par lookup
RDAP : bootstrap + authority). Redirect autorisé uniquement si scheme https,
hostname présent, non-local, non-réservé. Sinon `unavailable /
unsafe_redirect`. Deuxième redirect : ne pas suivre
(`unavailable / redirect_limit`). Pas de retry.

---

# 16. RDAP — PROJECTION

Extraire uniquement events registration/expiration/last changed, registrar
(`fn` vCard de la première entity `registrar`), status (max 10),
nameservers `ldhName` (max 10). Toujours `source_group=rdap`. Aucun scoring
dérivé. Interdit : `young_domain = malicious`, `old_domain = benign`.

---

# 17. DNS

Types et ordre exact : `A AAAA MX NS TXT`. Budget TOTAL 5 s (pas par type).
Maximum 10 valeurs par type. TXT > 512 caractères : pas d'Evidence partiellement
coupée. Mapping `A→osint_dns_a` etc., toujours `source_group=dns`. Interdit :
`AXFR ANY PTR enumeration subdomain brute force DNSSEC crawling DDR DoH
custom`. NXDOMAIN/NoAnswer sans valeur : `not_found`. Timeout :
`unavailable/timeout`. DNS egress actif documenté dans `docs/decisions.md`
(autorisé sur corpus public pour le POC, sans préjuger de la production).

---

# 18. CERTIFICATE TRANSPARENCY

Source `crt.sh`, uniquement pour `domain`. Une requête maximum :
`q=%.<registrable_domain>`, `output=json`, `deduplicate=Y`. Lecture bornée
`response.read(max_ct_response_bytes + 1)` ; si dépassement :
`unavailable/response_over_limit` sans parser. Best-effort (timeout, 5xx,
throttling documentés honnêtement).

---

# 19. CT — PROJECTION

`osint_ct_certificate_count` = entrées après `deduplicate=Y`. `not_before`
min/max → first/last. `name_value` : split lignes, strip, dédup, tri
lexicographique, max 20 → `osint_ct_dns_name`. Toujours
`source_group=certificate_transparency`. Aucun pivot.

---

# 20. CAPTURES ET PROVENANCE

HTTP (ThreatFox, RDAP, crt.sh) : bytes exacts sous `runs/.../captures/`,
jamais `Auth-Key`/headers secrets. RDAP redirect : réponse finale + hostnames
bootstrap/authority dans le bundle. DNS : JSON canonique. Par source :
`status reason requests_sent query_target response_ref response_sha256
collected_at`.

## 20.1 Bundle composite

`osint_bundle_<observable_digest>.json` avec `observable_id`,
`normalized_target`, `registrable_domain`, `sources{threatfox,rdap,dns,
certificate_transparency}` (seules applicables).
`ToolResult.response_ref` = nom du bundle, `response_sha256` = SHA-256 de ses
bytes. Chaque Evidence positive : `source_ref` vers la capture réelle +
JSON Pointer logique.

---

# 21. STATUT AGRÉGÉ

`ok` si ≥1 Evidence positive ; `unavailable` si aucune positive et ≥1 source
unavailable ; `not_found` si aucune positive et toutes applicables non-skipped
= not_found ; `skipped` si aucune applicable. `requests_sent` = somme exacte.
Reason synthétique :
`sources:threatfox=<status>;rdap=<status>;...` (sources applicables).

---

# 22. TOOL / EXECUTOR

`lookup_osint` uniquement pour les profils OSINT. Mapping
`"lookup_osint": "osint"`. `ProviderAdapterSet` reçoit `osint`. 1
`lookup_osint` = 1 `provider_tool_call`. Budgets inchangés
(`max_tool_calls=4`, `max_urlscan_calls=1`).

---

# 23. TIMEOUT OSINT

`ProviderToolExecutor._phase_timeout` : `osint → 40 s`. Chaque source :
`min(source_timeout, remaining_osint_deadline, remaining_agent_deadline)`.
Deadline épuisé : `unavailable/deadline`. Aucune grace period.

---

# 24. PROFILS

Exactement `agentic_core`, `agentic_context` (défaut, conserve le
comportement T19D), `agentic_osint`, `agentic_full`. Core/osint : RAG/QR/Vision
FORCÉS OFF (préprocessing non appelé, Settings inchangés). Context/full :
comportement contexte T19D selon Settings.

---

# 25. LISTE DE TOOLS

`tools_for_profile(profile)` : core/context = 4 tools T19D dans l'ordre exact
(`lookup_virustotal lookup_opencti scan_urlscan finalize_assessment`,
finalize toujours dernier) ; osint/full = 5 (insert `lookup_osint` avant
finalize). Hash core/context == hash T19D
`d2b97f27ed36177a5db9c89b3357cf6e5e1bbef4723f8a051f5fb792d9fbabe8`.

---

# 26. PROMPT OSINT

Ne pas modifier `prompts/agentic_assessment.txt`. Dans `src/agent/prompt.py`,
ajouter uniquement lorsque `lookup_osint` est exposé le bloc OSINT GUIDANCE
(hit ThreatFox = support d'inférence possible ; absence/unavailable = jamais
preuve de légitimité ; RDAP/DNS/CT = contexte, pas verdict ; dates
postérieures à l'email = état ultérieur possible ; plateforme mutualisée =
données de plateforme possibles).

---

# 27. RUNTIME FINGERPRINT

Architecture `agentic_core_v3`. Runtime contract exactement 10 champs
(architecture, profile, model, reasoning_effort, max_output_tokens_per_turn,
limits, effective_prompt_sha256, tool_schema_sha256,
assessment_schema_sha256, effective_capabilities avec rag,
rag_index_fingerprint, qr, vision, osint, threatfox_configured, psl_version).
`effective_capabilities` = configuration ACTIVE (profil ∧ Settings ∧ config
outils), jamais le résultat d'un tool. Manifest : + profile,
effective_capabilities ; `runtime_contract_sha256` diffère entre les 4
profils au minimum grâce au profil.

---

# 28. TOOL SCHEMA HASH

`tool_schema_sha256(tools)` sur `json.dumps(tools, ensure_ascii=False,
sort_keys=True, separators=(",",":"), allow_nan=False)`. Runtime : hash des
tools actifs de CE run (défaut = tools `agentic_context`).

---

# 29–49. (Inchangé v2.1 — résumé d'exécution)

Assessment schema inchangé (hash `eeb6…37021a2`). Verifier `compatible`
exigé pour les nouvelles evidences, `compatible_not_confirming` accepté pour
V09 (hit ThreatFox non confirmant — limite d'intégration documentée pour
T19E). Aucun pivot OSINT. Budgets/modèle/sampling inchangés. Tests offline
§35, profils §38, executor §39. Validation §40. Live smoke
`scripts/smoke_osint.py` sur `example.com` + `1.1.1.1`, sans LLM, crt.sh
best-effort §42.4. Aucun benchmark, gold_test fermé, Visual-79 interdit, T19E
non démarré. Statut terminal : `IMPLEMENTED_OSINT_PROFILES_VALIDATED`.
