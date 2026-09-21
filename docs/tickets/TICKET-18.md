# TICKET-18 — Évaluation finale scellée et bilan du POC

## GATE

Mesure terminale G6

## AMENDEMENT OPÉRATEUR (2026-09-21) — readiness/reproducibility smoke pré-T19

Aucun benchmark complet avant TICKET-19 : T18 NE lit PAS le full gold_test et N'exécute PAS de run complet. T18 devient un **smoke de freeze/readiness/reproducibility pré-T19** : vérifier et archiver les empreintes (code, config, prompts, schémas, index, lock), le gel des variantes, la procédure de recompute (reproduction exacte du smoke T14), la traçabilité de sélection et la checklist de handoff pour l'évaluateur T19. La première évaluation finale scellée du gold_test (ouverture par l'évaluateur dans un environnement distinct) est **T19**.

## OBJECTIF

Mesurer une seule fois les variantes décidées avant lecture du test.

## PRECONDITIONS / DÉPENDANCES

PASS G6 ; G7-A/B/C terminées ou non retenues ; code, configuration, prompts et index gelés. Le responsable évaluation matérialise le test après retrait de l’accès des agents de build.

## IN SCOPE

Run live final, recalcul métriques, analyse des résultats sans retouche système.

## OUT OF SCOPE

Modifier prompts/seuils/index/code au vu du test ; choisir après coup la meilleure variante ; réponses simulées.

## FILES ALLOWED

docs/poc_results.md ; runs/eval/gold_test_final/ ; runs/eval/gold_test_recomputed/. Aucun src/, tests/, config/, prompt/, corpus ou schema modifiable. Rapport final uniquement. Artefacts de validation sous runs/tickets/TICKET-18/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

CLI evaluate test avec experiment_lock. TriageReport et métriques identiques à la baseline. Comparaison appariée des variantes préenregistrées avec snapshots réels partagés ; test immuable.

## IMPLEMENTATION REQUIREMENTS

L’évaluateur exécute dans un environnement distinct et gelé. Enregistrer les pannes et la couverture ; garder erreurs et prédictions null dans les dénominateurs ; aucune exclusion après lecture. Si plusieurs variantes, préenregistrer l’ordre des appels et partager les observations d’outils réellement collectées et datées. Chaque classement Luna est réel. Aucun agent de build ne lit les emails test pour modifier le système.

## TESTS REQUIRED

Empreintes du test et du lock avant/après ; une sortie par sample_id ; validation des schemas ; métriques recompute identiques ; résultats par classe/source/chemin ; supports et intervalles ; coûts comprenant les retries.

## VALIDATION COMMANDS

```bash
python scripts/evaluate.py --mode recompute --from-run runs/eval/dev_smoke --out runs/eval/dev_smoke_recomputed
python scripts/check_gate.py G6
python scripts/check_gate.py G6 --record
```

## EXPECTED RESULTS

Exit 0, ou erreur explicite de disponibilité à documenter. Une reprise conserve les entrées/paramètres et ne permet aucun tuning. Aucune mesure simulée ne valide le POC.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Bilan réel répondant au succès/échec de l’hypothèse, valeur enrichissement, RAG public, vision et FINE-TUNE ; les défailances font partie du résultat.

## FAIL CONDITIONS

Test utilisé pour ajuster le système ; sélection après lecture des résultats ; métriques partielles présentées comme complètes ; empreintes divergentes.

## ARTEFACTS PRODUCED

Rapport final et archives authentiques, décision de poursuivre/arrêter/compléter selon preuves.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-18 — Évaluation finale scellée et bilan du POC, gate Mesure terminale G6. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
