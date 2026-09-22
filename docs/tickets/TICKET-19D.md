# TICKET-19D — Hardening minimal et freeze du runtime agentique

## STATUT

READY_TO_IMPLEMENT

Point de départ obligatoire :

- `main` contient PR #19 / T19C ;
- `main` contient la réconciliation post-merge du 22/09/2026 ;
- G6 est PASS sur un arbre propre ;
- T19C est `IMPLEMENTED_SMOKE_VALIDATED`.

Au démarrage, synchroniser `origin/main`, vérifier que l'arbre tracked est
propre et archiver le SHA exact utilisé.

T19D est un ticket de **hardening et de freeze uniquement**.

Il ne doit pas améliorer la qualité métier du modèle.
Il ne doit pas ajouter de nouvelle source OSINT.
Il ne doit pas modifier l'architecture.

---

## OBJECTIF

Préparer un runtime agentique stable et auditable avant les prochaines
extensions et avant T19E.

T19D doit uniquement :

1. corriger le bug connu du receipt du smoke Vision ;
2. figer explicitement les paramètres réellement utilisés par le runtime Qwen ;
3. figer les empreintes du prompt, des tools et du schéma ;
4. confirmer que les limites de run déjà prévues sont réellement injectables ;
5. observer, sans l'exploiter, l'éventuelle métadonnée de reasoning retournée
   par Akash/Qwen ;
6. vérifier que tout reste compatible avec T19C.

Principe :

> Aucun nouveau comportement métier.
> Aucun tuning.
> Aucun nouveau framework.
> Aucun nouveau tool.
> Aucun benchmark.

---

## ARCHITECTURE À CONSERVER STRICTEMENT

L'architecture reste exactement :

```text
email
  ↓
parser existant
  ↓
RAG public déterministe optionnel
  ↓
QR local + pixels Vision optionnels
  ↓
UN SEUL agent Qwen3.8 borné
  ↓
lookup_virustotal
lookup_opencti
scan_urlscan
finalize_assessment
  ↓
verify_assessment
  ↓
decide_policy
```

Il reste exactement :

- 1 agent ;
- 4 tools exposés au modèle ;
- aucun planner ;
- aucun critic ;
- aucun judge ;
- aucun second modèle ;
- aucun LangGraph supplémentaire ;
- aucun MCP runtime ;
- aucun browser ;
- aucun shell donné au modèle ;
- aucune mémoire persistante.

---

# 1. CORRIGER LE RECEIPT VISION

## Problème connu

Le smoke Vision live T16 a réellement réussi et transmis les pixels.

Cependant le receipt final pouvait contenir :

```json
{
  "response_sha256": null,
  "response_bytes": null
}
```

alors que la réponse réelle était bien présente et que son hash était écrit
dans le fichier metadata de la tentative.

La cause connue est un mismatch de nom/path entre le fichier réellement écrit
et le fichier recherché lors de la construction du receipt.

## À FAIRE

Corriger uniquement la récupération des metadata déjà produites.

Ne pas modifier :

- le transport ;
- le modèle ;
- le payload Vision ;
- les limites Vision ;
- la logique de retry ;
- les prompts.

Après une réponse fournisseur réellement reçue :

```text
smoke_result.json.response_sha256
```

doit être le SHA-256 réel de la réponse reçue.

Et :

```text
smoke_result.json.response_bytes
```

doit être la taille réelle de cette réponse.

Si aucune réponse fournisseur n'a été reçue, ces champs peuvent rester `null`.

Ne jamais fabriquer ces valeurs.

## TEST

Ajouter un test déterministe utilisant un fichier metadata local de fixture :

- metadata présent → hash et bytes repris exactement ;
- metadata absent → valeurs null ;
- aucun réseau.

---

# 2. FREEZE DES PARAMÈTRES LLM

Le runtime officiel reste :

```text
provider:
AkashML

endpoint:
https://api.akashml.com/v1/chat/completions

model:
Qwen/Qwen3.8-27B
```

Les paramètres agentiques T19D restent :

```text
tool_choice = auto
reasoning_effort = medium
response_format = absent
temperature = absent
top_p = absent
presence_penalty = absent
frequency_penalty = absent
seed = absent
```

Autrement dit :

> ne pas ajouter de paramètres de sampling que nous n'utilisons actuellement
> pas.

Le provider utilise ses valeurs par défaut pour les paramètres absents.

Le runtime ne doit PAS tester plusieurs températures, plusieurs `top_p`,
plusieurs reasoning efforts ou plusieurs budgets.

Ce serait du tuning et appartient à une expérience séparée.

---

# 3. LIMITES DE RUN

Le contrat par défaut reste :

```text
max_llm_turns = 5
max_tool_calls = 4
max_urlscan_calls = 1
max_agent_seconds = 300
max_single_llm_seconds = 90
max_tool_result_chars = 12000
reasoning_effort = medium
```

## IMPORTANT

T19D ne crée PAS une nouvelle couche de configuration.

`AgentLimits` reste l'unique objet Python représentant ces limites.

Le futur backend/API/frontend pourra simplement construire un `AgentLimits`
et le passer au runtime.

Il faut uniquement vérifier par tests que les valeurs suivantes peuvent déjà
être modifiées pour un run :

```text
max_llm_turns
max_tool_calls
max_agent_seconds
max_single_llm_seconds
max_tool_result_chars
```

et que :

- le runtime applique réellement la valeur ;
- le prompt annonce la même valeur ;
- le manifest archive la même valeur ;
- les messages de refus utilisent la même valeur.

### Exception

```text
max_urlscan_calls
```

reste structurellement fixé à :

```text
1
```

T19D ne change pas cette décision.

Aucune interface graphique n'est implémentée dans T19D.

---

# 4. FINGERPRINTS DU RUNTIME

Chaque run agentique doit permettre de savoir exactement quel contrat a été
utilisé.

Le manifest conserve les champs existants et ajoute seulement les empreintes
manquantes suivantes.

## 4.1 Prompt

Conserver :

```text
effective_prompt_sha256
```

Déjà implémenté.

Ne pas modifier le contenu de :

```text
prompts/agentic_assessment.txt
prompts/internal_assessment.txt
prompts/final_assessment.txt
```

---

## 4.2 Tool schema

Ajouter :

```text
tool_schema_sha256
```

Définition :

SHA-256 de la sérialisation JSON canonique exacte de `AGENT_TOOLS`.

Canonicalisation :

```python
json.dumps(
    AGENT_TOOLS,
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
    allow_nan=False,
).encode("utf-8")
```

---

## 4.3 Assessment schema

Ajouter :

```text
assessment_schema_sha256
```

Définition :

SHA-256 des bytes exacts de :

```text
schemas/assessment.schema.json
```

Ne pas hasher une reconstruction Pydantic.

Ne pas modifier ce fichier.

---

## 4.4 Runtime fingerprint

Ajouter :

```text
runtime_contract_sha256
```

Il est calculé sur un objet JSON canonique contenant exactement :

```json
{
  "architecture": "...",
  "model": "...",
  "reasoning_effort": "...",
  "max_output_tokens_per_turn": 0,
  "limits": {},
  "effective_prompt_sha256": "...",
  "tool_schema_sha256": "...",
  "assessment_schema_sha256": "..."
}
```

Les valeurs viennent du run réellement exécuté.

Ne pas inclure :

- timestamp ;
- run_id ;
- email ;
- résultat du modèle ;
- résultat des tools ;
- secrets.

Ainsi deux runs avec le même contrat runtime ont le même fingerprint.

Aucun second système de versioning n'est créé.

---

# 5. REASONING PROVIDER — OBSERVATION UNIQUEMENT

T19D ne construit AUCUNE mémoire de reasoning.

T19D ne transmet AUCUN reasoning précédent au tour suivant en dehors de ce que
le protocole actuel transmet déjà.

T19D ne dépend d'aucun champ propriétaire du provider.

## Comportement

Si la réponse Akash contient explicitement un champ de type :

```text
reasoning_content
```

ou équivalent déjà observable dans la réponse native :

le client peut seulement archiver :

```text
reasoning_content_present
reasoning_content_chars
reasoning_content_sha256
```

Le contenu lui-même :

```text
NE DOIT PAS être persisté
```

pour les emails réels/public corpus.

Ne pas interpréter ce texte.

Ne pas le réinjecter au tour suivant.

Ne pas modifier le prompt pour l'obtenir.

Si le provider ne retourne rien :

```text
reasoning_content_present = false
```

et le runtime continue normalement.

Les `reasoning_tokens` déjà retournés dans `usage` continuent d'être traités
comme actuellement.

---

# 6. PAS DE TUNING

T19D ne doit modifier aucun des éléments suivants :

```text
taxonomy
Assessment schema
verifier V01–V16
policy
classification thresholds
RAG k
RAG distance
Vision limits
QR behavior
tool descriptions métier
agentic prompt
V1 prompts
reasoning_effort
model
sampling
```

Une observation étrange pendant un smoke ne justifie aucune modification.

Exemple :

si Qwen produit d'abord :

```json
"assessment": "{...}"
```

au lieu d'un objet et se corrige après le refus typé existant :

ne rien changer.

Ce comportement sera mesuré à T19E.

---

# 7. OUT OF SCOPE

Explicitement interdit dans T19D :

- ThreatFox ;
- abuse.ch ;
- RDAP ;
- DNS ;
- Certificate Transparency ;
- nouveau tool ;
- nouveau profil agentique ;
- `agentic_context` ;
- `agentic_osint` ;
- `agentic_full` ;
- nouveau modèle ;
- comparaison de modèles ;
- BusinessContext ;
- historique de mailbox ;
- contexte organisationnel ;
- RAG privé ;
- fine-tuning ;
- benchmark dev complet ;
- gold_test ;
- Visual-79 ;
- G7-A/G7-B experimental closure ;
- frontend ;
- API frontend ;
- Docker ;
- Kubernetes ;
- base de données ;
- multi-agent.

La clé abuse.ch n'est pas utilisée dans ce ticket.

---

# 8. FILES ALLOWED

Modifications applicatives autorisées uniquement dans :

```text
src/agent/client.py
src/agent/models.py
src/agent/runner.py
src/agent/tools.py
scripts/smoke.py
tests/test_agent_client.py
tests/test_agent_runner.py
tests/test_agent_convergence.py
tests/test_vision.py
docs/tickets/TICKET-19D.md
```

Si aucun changement n'est nécessaire dans un fichier, ne pas le modifier.

Artefacts autorisés :

```text
runs/tickets/TICKET-19D/**
runs/gates/G7-B/smoke_vision/**
runs/agentic/**
```

Ne pas modifier :

```text
schemas/**
prompts/**
configs/**
src/graph.py
src/verify.py
src/policy.py
src/prompts.py
corpus/**
```

---

# 9. TESTS REQUIS

Ajouter uniquement les tests nécessaires aux nouvelles garanties.

Les tests doivent couvrir :

### Vision receipt

```text
response metadata présent
→ response_sha256 exact
→ response_bytes exact
```

et :

```text
response metadata absent
→ null/null
```

### Fingerprints

Même contrat :

```text
→ même runtime_contract_sha256
```

Une limite modifiée :

```text
→ runtime_contract_sha256 différent
```

Prompt conditionnel RAG/Vision différent :

```text
→ effective_prompt_sha256 différent
→ runtime_contract_sha256 différent
```

### Tool/schema hash

```text
tool_schema_sha256
```

doit correspondre exactement aux quatre tools réellement transmis au modèle.

```text
assessment_schema_sha256
```

doit correspondre exactement aux bytes du fichier gelé.

### AgentLimits

Au minimum tester des valeurs non-default pour :

```text
max_llm_turns
max_tool_calls
max_agent_seconds
max_single_llm_seconds
max_tool_result_chars
```

et vérifier que manifest/prompt/runtime utilisent bien ces valeurs.

Tester également que :

```text
max_urlscan_calls != 1
```

reste refusé.

---

# 10. VALIDATION OFFLINE

Exécuter :

```bash
python -m pytest \
  tests/test_agent_client.py \
  tests/test_agent_runner.py \
  tests/test_agent_convergence.py \
  tests/test_vision.py \
  -q
```

Puis :

```bash
python -m pytest -q
```

Puis :

```bash
python -m pip check
git diff --check
```

Aucun test ne doit ouvrir `gold_test`.

---

# 11. VALIDATION LIVE BORNÉE

Pas de benchmark.

Pas de batch complet.

Pas de retry sélectif.

## 11.1 Vision receipt

Charger la clé Akash depuis le macOS Keychain dans le même shell, sans
l'afficher.

Exécuter UNE fois :

```bash
python scripts/smoke.py vision --require-configured
```

Vérifier :

```text
status = live_ok
requested_model = Qwen/Qwen3.8-27B
returned_model = Qwen/Qwen3.8-27B
visual_blocks_in_request >= 1
response_sha256 != null
response_bytes > 0
```

Ne pas relancer uniquement pour obtenir un meilleur résultat métier.

## 11.2 Reasoning metadata

Ne pas créer un second run uniquement pour obtenir du reasoning.

Si le smoke live réalisé ci-dessus ou un artefact live agentique T19C
compatible permet d'observer proprement les métadonnées provider :

archiver uniquement :

```text
reasoning_content_present
reasoning_content_chars
reasoning_content_sha256
```

Sinon noter :

```text
reasoning_metadata = not_observed
```

Ce résultat est NON BLOQUANT.

Aucun reasoning n'est réutilisé.

---

# 12. ARTEFACT T19D

Créer :

```text
runs/tickets/TICKET-19D/report.md
runs/tickets/TICKET-19D/status.json
```

`status.json` doit contenir au minimum :

```json
{
  "ticket": "TICKET-19D",
  "status": "IMPLEMENTED_FREEZE_VALIDATED",
  "base_commit": "...",
  "head_commit": "...",
  "offline_tests": "...",
  "vision_smoke": "...",
  "reasoning_metadata": "observed|not_observed",
  "prompts_changed": false,
  "schemas_changed": false,
  "architecture_changed": false,
  "gold_test_opened": false,
  "visual79_run": false,
  "full_benchmark_run": false
}
```

Si le smoke Vision ne peut pas être exécuté pour une raison externe réelle :

```text
IMPLEMENTED_WAITING_FOR_LIVE_HARDENING_SMOKE
```

et documenter exactement pourquoi.

Ne simuler aucune preuve.

---

# 13. ACCEPTANCE CRITERIA

T19D est `IMPLEMENTED_FREEZE_VALIDATED` uniquement si :

1. les tests ciblés passent ;
2. la suite offline complète passe ;
3. `pip check` passe ;
4. `git diff --check` passe ;
5. le bug du receipt Vision est corrigé ;
6. un nouveau smoke Vision réel confirme `response_sha256` et
   `response_bytes` ;
7. les hashes prompt/tool/schema/runtime sont cohérents ;
8. les limites non-default testées sont réellement appliquées ;
9. `max_urlscan_calls` reste fixé à 1 ;
10. aucun prompt/schema/policy/verifier n'a changé ;
11. aucune nouvelle capability métier n'a été ajoutée ;
12. aucun benchmark complet n'a été lancé ;
13. `gold_test` est resté fermé ;
14. Visual-79 n'a pas été exécuté.

---

# 14. FAIL CONDITIONS

FAIL si :

- un hash est inventé au lieu d'être calculé sur les bytes réels ;
- un secret apparaît dans un artefact ;
- un prompt est modifié ;
- le schema Assessment est modifié ;
- les paramètres LLM sont tunés ;
- un nouveau tool est ajouté ;
- le reasoning est persisté en clair ;
- le reasoning est réinjecté ;
- un benchmark complet est exécuté ;
- gold_test est ouvert ;
- Visual-79 est exécuté ;
- une source OSINT+ est ajoutée ;
- une réponse fournisseur simulée est présentée comme live.

---

# 15. FIN DU TICKET

Après validation :

```text
T19D = IMPLEMENTED_FREEZE_VALIDATED
```

Puis STOP.

Ne pas :

- commencer T19E ;
- ajouter ThreatFox ;
- ajouter RDAP ;
- ajouter DNS ;
- ajouter Certificate Transparency ;
- créer les profils agentic_* ;
- modifier le frontend.

Ces étapes nécessitent des tickets séparés et une décision opérateur.

---

# CODEX / OPENCODE EXECUTION PROMPT

Exécute uniquement `TICKET-19D — Hardening minimal et freeze du runtime
agentique`.

Commence depuis un `origin/main` propre contenant la réconciliation
post-T19C et le G6 PASS propre du 22/09/2026.

Lis :

1. `AGENTS.md`
2. ce ticket
3. `docs/architecture.md`
4. `docs/contracts.md`
5. `docs/decisions.md`
6. `docs/gates.md`
7. `docs/tickets/TICKET-19A.md`
8. `docs/tickets/TICKET-19B.md`

Implémente exactement ce ticket.

Principe directeur :

> solution minimale ; aucune nouvelle architecture.

Tu dois uniquement :

- corriger le receipt Vision ;
- ajouter les fingerprints manquants ;
- vérifier les limites AgentLimits ;
- archiver les paramètres réels du runtime ;
- observer passivement les metadata reasoning si elles sont disponibles ;
- lancer les validations définies dans le ticket.

Ne modifie PAS :

- prompts ;
- schemas ;
- verifier ;
- policy ;
- classification ;
- modèle ;
- reasoning effort ;
- sampling ;
- RAG ;
- QR ;
- Vision métier ;
- nombre ou nature des tools.

Ne touche pas à :

- ThreatFox ;
- abuse.ch ;
- RDAP ;
- DNS ;
- Certificate Transparency ;
- frontend.

Ne lance :

- aucun benchmark complet ;
- aucun gold_test ;
- aucun Visual-79 ;
- aucun T19E.

N'effectue aucun retry sélectif.

À la fin, fournis :

- base SHA ;
- head SHA ;
- fichiers modifiés ;
- tests exécutés avec résultats exacts ;
- résultat du smoke Vision ;
- valeurs des fingerprints ;
- résultat de l'observation reasoning ;
- confirmation que prompts/schemas/V1 sont inchangés ;
- artefacts T19D ;
- statut final.

Puis arrête-toi.
