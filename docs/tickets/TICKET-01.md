# TICKET-01 — Squelette, configuration et contrats

## GATE

G0

## OBJECTIF

Installer le projet minimal et figer les objets échangés.

## PRECONDITIONS / DÉPENDANCES

Aucun ticket. Dossier de spécification présent dans docs/, prompts/, schemas/.

## IN SCOPE

Package src, pyproject, venv documenté, dépendances baseline, modèles et schemas, configuration, pytest et règles AGENTS.

## OUT OF SCOPE

Parsing métier, classification, enrichissements, RAG, vision et corpus.

## FILES ALLOWED

AGENTS.md; .gitignore; .env.example; pyproject.toml; requirements.lock; README.md; configs/gate.yaml; configs/policy.yaml; configs/tools.yaml; src/__init__.py; src/config.py; src/state.py; tests/conftest.py; tests/test_bootstrap.py; tests/test_contracts.py; docs/contracts.md; docs/gates.md; scripts/check_gate.py. Artefacts de validation sous runs/tickets/TICKET-01/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

load_settings(env_file: Path | None) -> Settings ; new_state(input_path: Path, source_profile: str, config_sha256: str) -> EmailTriageState. Modèles et défauts exactement docs/contracts.md et schemas/*.json. Contrats objets stricts, champs nullables distincts des listes vides.

## IMPLEMENTATION REQUIREMENTS

Python 3.11, setuptools déclare explicitement le package src. SecretStr pour clés ; config publique exportable sans secrets. Aucun secret lu dans le contexte Codex : les tests utilisent présence/absence sans afficher les valeurs. Générer le lock réellement résolu, puis vérifier une installation propre. check_gate reste une liste fixe de contrôles et reçus, sans scheduling ni agents. Créer uniquement dossiers vides pour les composants futurs, sans fonctions factices produisant des verdicts.

## TESTS REQUIRED

Imports après installation ; absence de clé admise au bootstrap ; booléens et valeurs YAML invalides rejetés ; defaults indépendants entre deux états ; six classes exactes ; NaN/inf et champs inconnus rejetés ; serialization JSON ; un objet de contrat minimal valide et plusieurs objets invalides (pas des réponses API).

## VALIDATION COMMANDS

```bash
python -m pip install -e ".[dev]"
python -m pip check
python -m pytest tests/test_bootstrap.py tests/test_contracts.py -q
```

## EXPECTED RESULTS

Trois exit codes 0 ; au moins un test collecté par fichier, aucun failed/xfailed ; config charge sans clé ; schemas des modèles conformes aux contrats livrés.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Installation reproductible, import src hors dépendance au répertoire tests, aucune infrastructure supplémentaire. Ticket 01 DONE ne signifie pas G0 PASS : attendre 02.

## FAIL CONDITIONS

Conflit de dépendances, enum divergent, clés exposées, comportement métier anticipé ou schema assoupli.

## ARTEFACTS PRODUCED

Squelette, lock, configuration, modèles/schemas, tests et documentation ; logs sous runs/tickets/TICKET-01/.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-01 — Squelette, configuration et contrats, gate G0. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
