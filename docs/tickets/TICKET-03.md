# TICKET-03 — Parser déterministe et fixtures MIME

## GATE

G1

## OBJECTIF

Extraire fidèlement les emails et produire les fixtures de référence.

## PRECONDITIONS / DÉPENDANCES

PASS G0 vérifié par check_gate.

## IN SCOPE

Headers, bodies, liens/mismatch, pièces/hashes, métadonnées images, limites et fixtures contrôlées.

## OUT OF SCOPE

Luna, services externes, classification, téléchargement distant, décodage QR/OCR runtime.

## FILES ALLOWED

src/parsing.py; tests/test_parsing.py; tests/conftest.py; tests/fixtures/manifest.json; tests/fixtures/phishing_simple.eml; tests/fixtures/legitimate_newsletter.eml; tests/fixtures/spam_promo.eml; tests/fixtures/bec_fraud.eml; tests/fixtures/threat_extortion.eml; tests/fixtures/spear_phishing_targeted.eml; tests/fixtures/attachment_suspicious.eml; tests/fixtures/prompt_injection.eml; tests/fixtures/shared_infra_benign.eml; tests/fixtures/malicious_url_redirect.eml; tests/fixtures/qr_phishing.eml; tests/fixtures/visual_prompt_injection.eml; tests/fixtures/phishing_auth_pass.eml; tests/fixtures/malformed_reasonable.eml; docs/fixtures.md; docs/contracts.md. Artefacts de validation sous runs/tickets/TICKET-03/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

parse_email(path: Path, limits: ParseLimits) -> ParsedEmail ; parse_bytes(data: bytes, input_format: str) -> ParsedEmail. Types/normalisation et limites docs/architecture.md §1.5 et docs/contracts.md. Les noms de pièces ne deviennent jamais chemins.

## IMPLEMENTATION REQUIREMENTS

Toutes les fixtures suivent docs/fixtures.md. Les PNG/QR statiques peuvent être préparés lors de l’auteur des fixtures avec un outil local, sans ajouter de dépendance image au runtime baseline. Hashes sur bytes décodés et hash email sur original. Répétitions de headers préservées ; auth trust reported_unverified par défaut. Projection LLM ne sera pas créée ici.

## TESTS REQUIRED

Toutes les fixtures ; hash attendu du payload fixe ; URL exact query/HTML entity ; href texte non URL ; cid/multipart ; filename traversal ; taille/profondeur ; erreurs charset/Base64 ; image distante jamais chargée. Interdire le réseau pendant les tests parser (une tentative réseau fait échouer le test).

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G0
python -m pytest tests/test_parsing.py -q
python scripts/check_gate.py G1 --record
```

## EXPECTED RESULTS

Exit 0 ; fixtures parsées ou erreur structurée prévue, jamais exception non gérée ; hashes et URLs exacts ; aucun appel réseau ; receipt G1 PASS.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

G1 PASS, toutes les données ont source_ref ; aucune reconstruction de header absent ; aucune interprétation image inventée.

## FAIL CONDITIONS

URL/IOC ajouté sans origine ; payload exécuté ; extraction de fichier hors dossier ; hash calculé sur le Base64 au lieu du contenu ; téléchargement.

## ARTEFACTS PRODUCED

Parser, 14 fixtures, manifest des attentes et logs G1.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-03 — Parser déterministe et fixtures MIME, gate G1. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
