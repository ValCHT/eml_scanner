# TICKET-05 — Complexity gate à trois règles

## GATE

G3

## OBJECTIF

Rendre le choix simple/complex testable et explicite.

## PRECONDITIONS / DÉPENDANCES

PASS G2 et réponses réelles du runtime G2 officiel `Qwen/Qwen3.8-27B` archivées.

## IN SCOPE

R1/R2/R3, seuils, reasons et résultats de gate par fixture.

## OUT OF SCOPE

Nouveau LLM, réputation, allowlist bénigne automatique, seuils choisis à partir du test.

## FILES ALLOWED

src/gate.py; configs/gate.yaml; tests/test_gate.py; docs/decisions.md. Artefacts de validation sous runs/tickets/TICKET-05/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

decide_gate(parsed, internal, config) -> GateResult ; expressions exactes docs/decisions.md §4.1 ; aucune dépendance réseau. SIMPLE implique R1=R2=R3=false.

## IMPLEMENTATION REQUIREMENTS

Configuration BASELINE V0 provisoire et non calibrée : aucun réglage avant première baseline G6, puis ajustements uniquement sur gold_dev. Mesurer en G6 % SIMPLE/COMPLEX, qualité et coût de chaque chemin. Newsletter avec URL pertinente → COMPLEX attendu ; aucune nouvelle heuristique/allowlist. Reasons stables sans doublons. Frontières strictes <0.90 et <0.20, égalité autorisée ; URL pertinente/attachement non inline ; parser/information manquante. Vérifier le comportement sur les réponses réelles G2, sans imposer des scores factices. Les entrées de fonction numériques construites pour frontières ne sont pas des résultats d’évaluation.

## TESTS REQUIRED

Chaque règle isolée, toutes combinaisons, frontières 0.899999/0.90 et 0.199999/0.20, None, image essentielle, tracking, absence de lien ; répétabilité bit à bit ; entrées déterministes couvrant SIMPLE et COMPLEX ; toutes les réponses réelles du runtime G2 officiel Qwen3.8 repassées dans le gate sans modifier leurs scores.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G2
python -m pytest tests/test_gate.py -q
python scripts/check_gate.py G3 --record
```

## EXPECTED RESULTS

Exit 0 ; toutes raisons et branches déterministes conformes ; distribution des sorties G2 réelles archivée. Si aucune n'est SIMPLE, enregistrer `simple_path_live_observed=false` et la limitation prévue dans le reçu G3 ; ne pas chercher un autre email, ne pas modifier les seuils et ne pas bloquer G4 pour ce seul motif.

## SECURITY INVARIANTS

Aucune réponse LLM/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

PASS G3 ; la décision est entièrement déterministe ; simple ne signifie pas légitime.

## FAIL CONDITIONS

Branchement décidé par LLM, appels externes, ambiguïté des frontières, changement silencieux des seuils.

## ARTEFACTS PRODUCED

Gate, config, table fixture→résultat réel, preuves G3 et indicateur `simple_path_live_observed`.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-05 — Complexity gate à trois règles, gate G3. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
