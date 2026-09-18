# TICKET-02 — Client Luna réel et clôture du bootstrap

## GATE

G0

## OBJECTIF

Valider le transport OpenAI-compatible sans logique SOC.

## PRECONDITIONS / DÉPENDANCES

TICKET-01 DONE ; imports/config/schemas vérifiés.

## IN SCOPE

POST réel, structured output minimal, captures d’usage et erreurs, smoke et fermeture G0.

## OUT OF SCOPE

Parser email, prompt SOC, adaptateurs externes, réponse synthétique pour remplacer Luna.

## FILES ALLOWED

src/llm.py; scripts/smoke.py; scripts/validate_reports.py; tests/test_llm_client.py; tests/test_bootstrap.py; docs/contracts.md; README.md; scripts/check_gate.py. Artefacts de validation sous runs/tickets/TICKET-02/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

complete_json(messages: list[dict], schema: dict, effort: str, max_output_tokens: int, deadline: float) -> (dict | None, CallRecord). Endpoint exact de Settings ; headers d’authentification construits hors messages. Modèle runtime openai/gpt-5.6-luna.

## IMPLEMENTATION REQUIREMENTS

Une réponse réelle avec un petit schema {ok:boolean}. Refus/finish_reason/type inattendu traités comme erreurs. Aucun fallback de modèle, de fournisseur ou de structured outputs. Capture model/usage/response hash sans request headers. --if-configured distingue absent credentials (pending) d’un échec quand la clé existe. Le receipt G0 mentionne le pending et G2 devra le lever.

## TESTS REQUIRED

Validation locale d’un payload sans secret ; vraie requête si configurée ; rejet JSON invalide au validateur ; timeout réel à délai court hors quota abusif ; logs inspectés avec secret canari local ; erreurs CLI lisibles.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_llm_client.py tests/test_bootstrap.py tests/test_contracts.py -q
python scripts/smoke.py luna --if-configured
python scripts/check_gate.py G0 --record
```

## EXPECTED RESULTS

Tests locaux exit 0 ; smoke réel ok si configuré, ou statut explicite live_pending si absent ; une clé fournie qui échoue produit exit non nul et G0 FAIL/BLOCKED. Reçu G0 PASS seulement selon docs/gates.md.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

G0 complet, client minimal réel, pas de donnée email ni enrichissement ; possibilité de G1 autorisée par reçu.

## FAIL CONDITIONS

Appel réel échoué avec credentials présents ; proxy qui refuse le schema ; valeur de secret dans logs ; résultat prétendu réel sans réponse.

## ARTEFACTS PRODUCED

Client, smoke, archives authentiques éventuelles et runs/gates/G0/gate.json.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-02 — Client Luna réel et clôture du bootstrap, gate G0. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
