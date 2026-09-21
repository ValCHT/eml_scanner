# TICKET-17 — Décision quantitative sur fine-tuning (optionnel, post-T19E)

## GATE

G7-C

## AMENDEMENT OPÉRATEUR (2026-09-21, trajectoire accélérée) — optionnel, après T19E

T17 est **optionnel** et intervient **après T19E** (le premier benchmark complet), sans bloquer aucune autre étape. Il analyse les familles d'erreurs et le besoin de spécialisation à partir du benchmark T19E et des observations accumulées (smokes T14/T15/T16, diagnostics) ; la décision porte sur les modes d'échec de l'architecture retenue par T19E. Aucun run complet supplémentaire n'est lancé et aucune retouche du système n'est faite au vu des résultats. INCONCLUSIVE est un résultat valide.

## OBJECTIF

Décider si une expérimentation de spécialisation mérite d’être lancée.

## PRECONDITIONS / DÉPENDANCES

T19E terminée (benchmark complet + rerun de la V1 fixe archivés ; run dev complet retenu déposé sous `runs/eval/t19e_dev`) ; décision explicite de mener l'analyse optionnelle (T17 ne conditionne plus aucune étape).

## IN SCOPE

Analyse des familles d’erreurs, besoin de spécialisation et candidats/faisabilité Phase 2 séparés du modèle Luna imposé au POC, sur la base du benchmark T19E et des diagnostics accumulés.

## OUT OF SCOPE

Entraîner un modèle, lire le test, recommander un tuning pour compenser données absentes.

## FILES ALLOWED

docs/fine_tuning_decision.md; configs/experiment_lock.json. Aucune modification de src/. Artefacts de validation sous runs/tickets/TICKET-17/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

Document contenant FINE-TUNE=YES|NO|INCONCLUSIVE, nombre évalué, nombre d’erreurs, familles, stabilité sur reruns réels, gain potentiel, faisabilité modèle/proxy et conditions de révision. Les résultats T19E analysés proviennent du run dev complet retenu `runs/eval/t19e_dev` (recompute `runs/eval/t19e_dev_recomputed`) ; le recompute de préparation écrit `runs/eval/t19e_for_ft_decision` et constitue la vérification d’artefact de la gate G7-C. Si YES : target_failure_modes, why_prompting_is_insufficient, why_retrieval_is_insufficient, why_enrichment_is_insufficient, training_data_needed, estimated_number_of_examples, candidate_models, evaluation_protocol, non_regression_requirements, estimated_training_cost, phase_2_go_no_go_conditions ; exigences détaillées docs/evaluation.md §8.5.

## IMPLEMENTATION REQUIREMENTS

Appliquer docs/evaluation.md §8.5. Distinguer défaut stable de taxonomie/instruction et défaut de parsing/outils/retrieval/gate/annotation. Utiliser les logs réels (T19E, dev, smokes). La fiche Luna indique que le fine-tuning n’est pas pris en charge : un YES sur le besoin ne vaut pas faisabilité sur ce modèle. Inclure « Qwen3.8-27B — candidat vérifié au 18/09/2026 » avec sources et statut de docs/evaluation.md : poids ouverts, dense, texte+image, scénario PEFT/QLoRA Phase 2 à valider techniquement, intérêt multimodal/quishing à benchmarker. Aucun modèle retenu sans benchmark ; distinguer besoin/candidat/faisabilité/bénéfice. Aucune dépendance Qwen, aucun téléchargement, runtime ou entraînement dans ce POC ; ne pas conclure « fine-tunons Luna ».

## TESTS REQUIRED

Comparer les comptes à metrics.json ; chaque erreur citée possède un sample_id dev et des preuves. Aucun test consulté. Vérifier les critères YES/NO/INCONCLUSIVE ; ne pas inventer des reruns absents. Si YES, vérifier la présence et le contenu des onze champs, les hypothèses d’estimation et les conditions go/no-go ; UNKNOWN explicite si non vérifié, jamais coût ou expérience inventés.

## VALIDATION COMMANDS

```bash
python scripts/evaluate.py --mode recompute --from-run runs/eval/t19e_dev --out runs/eval/t19e_for_ft_decision
python scripts/check_gate.py G7-C --record
```

## EXPECTED RESULTS

Exit 0 ; comptes concordants ; décision explicite, INCONCLUSIVE si preuve insuffisante ; aucun code d’entraînement ; reçu G7-C PASS archivé si cette expérience optionnelle est menée ; T17 ne conditionne aucune étape (optionnel, après T19E).

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Conclusion quantitative traçable avec séparation besoin/faisabilité ; aucune donnée test utilisée.

## FAIL CONDITIONS

Fine-tuning prescrit sans erreur répétée stable ; absence d’annotations cachée ; chiffre sans logs.

## ARTEFACTS PRODUCED

Note de décision, variantes finales préenregistrées dans experiment_lock et runs/gates/G7-C/gate.json si G7-C menée ; sinon option explicitement non retenue.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-17 — Décision quantitative sur fine-tuning (optionnel, après T19E), gate G7-C. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus (T19E archivée), implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
