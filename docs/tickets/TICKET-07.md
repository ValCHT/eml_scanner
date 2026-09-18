# TICKET-07 — OpenCTI : lecture réelle et correspondance exacte

## GATE

G4

## OBJECTIF

Exposer une CTI utilisable sans confondre présence et malveillance.

## PRECONDITIONS / DÉPENDANCES

PASS G3 ; TICKET-06 DONE ; token OpenCTI valide et observable connu dans instance réelle.

## IN SCOPE

pycti aligné, lecture GraphQL, projection bornée, comparaison exacte et erreurs.

## OUT OF SCOPE

Création/modification observable, mutation GraphQL, parcours de graphe, déploiement OpenCTI, RAG CTI.

## FILES ALLOWED

src/tools/opencti.py; configs/tools.yaml; tests/test_opencti.py; scripts/smoke.py; docs/contracts.md; requirements.lock; pyproject.toml si alignement pycti nécessaire. Artefacts de validation sous runs/tickets/TICKET-07/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

OpenCTIAdapter.lookup(query, context) -> ToolResult. Liste bornée first=10/getAll=False si acceptée ; comparer type et valeur/algorithme hash, ne pas sélectionner arbitrairement le premier résultat.

## IMPLEMENTATION REQUIREMENTS

Capturer version/schéma minimal réellement observés et lock correspondant. Ne pas dépendre d’un feed supposé. Tous appels GraphQL query, aucun mutation. Label/score/date/révocation exposés s’ils existent ; références de la source sans navigation vers leur contenu. Mode OSINT et match EXACT/GENERIC explicite.

## TESTS REQUIRED

Vrai match connu ; recherche sans match ; valeur proche mais différente dans capture réelle si disponible, sinon validateur d’égalité sur objets locaux ; timeout court réel ; erreur token contrôlée ; projection partielle. Rejeter les mutations avant émission. Capturer reset/token expiré comme unavailable.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_opencti.py --live -q
python scripts/smoke.py opencti --require-configured
python -m pip check
```

## EXPECTED RESULTS

Exit 0 ; un succès et une absence réels ; aucune mutation ; instance/down n’est jamais remplacée par une réponse fabriquée.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Lookup réellement validé ; unknown/score faible/presence ne décide pas phishing ; ticket 07 DONE.

## FAIL CONDITIONS

Full text search pris pour exact match, droits supposés, réponse inventée, ajout automatique d’observable à l’instance.

## ARTEFACTS PRODUCED

Adaptateur, contrat de projection et captures G4/OpenCTI.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-07 — OpenCTI : lecture réelle et correspondance exacte, gate G4. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
