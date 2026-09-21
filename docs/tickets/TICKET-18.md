# TICKET-18 — Gel, readiness et reproductibilité pré-T19

## GATE

Readiness pré-T19 (la mesure terminale scellée est T19)

## AMENDEMENT OPÉRATEUR (2026-09-21) — readiness/reproducibility smoke pré-T19

Aucun benchmark complet avant TICKET-19 : T18 NE lit PAS gold_test et N'exécute PAS de run complet (ni 83 dev, ni Visual-79, ni test). T18 vérifie le gel (code, configs, prompts, schémas, lock), reproduit hors ligne le smoke borné T14 (zéro appel fournisseur), vérifie la traçabilité de sélection et produit la checklist de handoff pour l'évaluateur T19. La première évaluation finale scellée du gold_test (ouverture par l'évaluateur dans un environnement distinct) est **T19**.

## OBJECTIF

Établir que tout est gelé, reproductible et prêt pour la mesure terminale T19 : empreintes vérifiées, smoke borné reproduit à l'identique, procédure T19 préenregistrée. Aucune lecture de gold_test, aucun run complet.

## PRECONDITIONS / DÉPENDANCES

PASS G6 (reçu enregistré) ; G7-A/B/C terminées ou explicitement non retenues ; smoke T14 et son recompute archivés ; code, configuration, prompts et schémas inchangés depuis la dernière exécution vérifiée. Le responsable évaluation matérialise le test T19 après retrait de l'accès des agents de build.

## IN SCOPE

Inventaire et vérification des empreintes du gel (commit/arbre, prompts, schémas, gate/policy/tools, evaluation.yaml, experiment_lock.json, requirements.lock, index RAG éventuel) ; reproduction exacte hors ligne du smoke borné (`--mode recompute`, zéro appel) ; vérification de l'identité de la sélection (`selected_sample_ids` == règle déterministe) ; plan d'exécution T19 (environnement d'évaluation distinct, ouverture du test, ordre des variantes préenregistré, dénominateurs complets, coûts/retries, budgets gelés) ; checklist de handoff et limitations publiées.

## OUT OF SCOPE

Lecture ou ouverture de gold_test ; tout run complet (83 dev, Visual-79, test) ; appels fournisseur sur le holdout ; modification de prompts/seuils/index/code/config au vu des résultats ; choix a posteriori d'une variante ; réponses simulées ; tuning.

## FILES ALLOWED

docs/evaluation.md ; runs/tickets/TICKET-18/ ; runs/eval/pre_t19_recompute/ (reproduction de contrôle). Aucun src/, tests/, configs/, prompts/, corpus ou schemas modifiable. Aucun fichier de résultat final : le bilan chiffré appartient à T19.

## INTERFACES / CONTRACTS

`python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke --out runs/eval/pre_t19_recompute` (offline, `provider_calls=0`, métriques identiques) ; `python scripts/check_gate.py G6` (reçu vérifié). Le plan T19 préenregistre l'ordre des variantes et les commandes exactes ; le test n'est ouvert qu'à T19 par l'évaluateur.

## IMPLEMENTATION REQUIREMENTS

Vérifier chaque empreinte et consigner les valeurs ; toute divergence est BLOCKED, jamais contournée. La reproduction doit être exacte : métriques identiques, identité de sélection vérifiée, zéro appel réseau/fournisseur. Aucune retouche de code/config/prompt/schéma après vérification ; une retouche invalide la vérification et exige une nouvelle passe complète. Consigner la procédure T19 et les limitations dans le rapport de readiness. Aucun agent de build ne lit les emails test pour modifier le système.

## TESTS REQUIRED

Empreintes avant/après identiques ; recompute identique (métriques + identité de sélection) ; refus de toute lecture gold_test (test existant) ; refus d'un run live sans `--sample-profile` explicite ; aucun run complet déclenché.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G6
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke --out runs/eval/pre_t19_recompute
python -m pytest tests/test_evaluation.py -q
```

## EXPECTED RESULTS

Exit 0 ; empreintes inchangées ; recompute exact ; checklist T19 complète ; gold_test non ouvert ; aucun run complet exécuté. Une divergence d'empreinte ou un recompute non identique = FAIL/BLOCKED documenté, sans retouche du système.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d'entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Gel vérifié et reproductibilité démontrée hors ligne ; procédure T19 prête ; aucune mesure complète exécutée ; aucune lecture de gold_test.

## FAIL CONDITIONS

Test utilisé pour ajuster le système ; sélection après lecture des résultats ; métriques partielles présentées comme complètes ; empreintes divergentes non traitées ; run complet lancé avant T19.

## ARTEFACTS PRODUCED

Rapport de gel/readiness et checklist de handoff (runs/tickets/TICKET-18/), reproduction de contrôle, reçu G6 vérifié.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-18 — gel, readiness et reproductibilité pré-T19 (la mesure terminale scellée est T19 ; aucun benchmark complet avant T19). Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s'il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Ne lis jamais gold_test : le run final scellé appartient à T19. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l'utilisateur n'est nécessaire.
