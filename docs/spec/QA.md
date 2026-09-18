# Vérification finale et gel V1.2

18/09/2026 — **V1.2 READY FOR IMPLEMENTATION: YES**

V1.2 est un micro-patch de la V1.1 gelée. Il applique uniquement deux findings validés après contre-revue Claude : suppression du deadlock stochastique sur la présence d'un chemin SIMPLE live avant G6, et extension de l'audit d'entrée aux appels FINAL afin de rendre l'ablation A/B/C vérifiable. Aucun changement de prompts, schemas, graphe, règles R1–R3, V01–V16, policy, taxonomie, enrichissements ou liste de tickets.

## V12-01 — CLOSED — G3/G5 ne dépendent plus d'un SIMPLE live stochastique

- Les branches SIMPLE et COMPLEX sont prouvées par tests déterministes du gate/plumbing, hors métriques métier.
- Toutes les sorties Luna G2 réelles restent passées dans le gate et archivées telles quelles.
- Si aucune sortie G2 réelle n'est SIMPLE, `simple_path_live_observed=false` et une limitation sont enregistrés ; G3 peut PASS sans changer les seuils BASELINE V0.
- G5 teste le plumbing des deux branches mais le batch live suit uniquement les décisions réelles. L'absence de SIMPLE live reste non bloquante avant G6.
- G6 mesure la vraie couverture SIMPLE/COMPLEX sur gold_dev ; support SIMPLE=0 rend sa qualité non estimable, pas la gate invalide.

## V12-02 — CLOSED — audit FINAL requis pour B−A / C−B

- `docs/contracts.md` §2.6.1 couvre désormais INTERNAL et FINAL.
- FINAL ajoute `internal_evidence_count_sent`, `external_evidence_count_sent`, `tool_status_digest`, `rag_case_count_sent`, `visual_count_sent`.
- Même minimisation : request body exact persisté uniquement pour fixtures ; corpus/public/private = hashes/compteurs/digests calculés en mémoire sans body complet sur disque.
- B doit démontrer zéro evidence externe, zéro RAG et zéro pixel ; C doit transmettre les evidences externes admissibles quand le bundle en produit.
- Un mismatch entre variante annoncée et audit invalide B−A/C−B et fait échouer G6 ; aucune réparation silencieuse.

## Findings de contre-revue non appliqués

- Aucune couche `build_wire_schema` ajoutée : la compatibilité exacte Structured Outputs du proxy Orange reste volontairement testée par les smokes G0/G2 ; prompts/schemas restent gelés.
- `opencode.jsonc` n'est pas modifié par V1.2 ; le patch concerne uniquement les deux findings expérimentaux retenus.

## Contrôles de cohérence

| Contrôle | Résultat |
|---|---|
| Tickets | 18 conservés ; TICKET-05, 09, 11 et 14 modifiés ; aucun ajout/split. |
| Prompts/schemas | Inchangés. |
| Architecture | Un processus, un StateGraph séquentiel, deux appels Luna nominaux maximum inchangés. |
| G3 | Branches déterministes testables ; absence de SIMPLE live non bloquante et traçable. |
| G5 | Pipeline live inchangé ; audit FINAL vérifié ; absence de SIMPLE live avant G6 non bloquante. |
| G6 | A/B/C réelle, audits FINAL obligatoires, couverture SIMPLE/COMPLEX publiée. |
| Confidentialité | Payload complet fixture uniquement ; corpus/public/private jamais persisté. |
| Gold/holdout | Règles V1.1 inchangées. |
| G7 | Optionnalité inchangée. |

BLOCKER restant : **0**.

Les gates runtime restent **NOT_STARTED**. La suite de construction autorisée commence à **TICKET-01**.
