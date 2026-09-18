# TICKET-10 — Vérificateur et policy déterministes

## GATE

G5

## OBJECTIF

Empêcher une preuve invalide de devenir IOC ou décision AUTO.

## PRECONDITIONS / DÉPENDANCES

TICKET-09 DONE ; PASS G4 ; captures réelles internal/final.

## IN SCOPE

V01–V16, unsupported_claims, filtrage des propositions, action ordonnée et raisons.

## OUT OF SCOPE

Nouveau modèle de vérification, correction cachée de preuves/labels, action réelle sur messagerie.

## FILES ALLOWED

src/verify.py; src/policy.py; configs/policy.yaml; tests/test_verify.py; tests/test_policy.py; docs/decisions.md. Artefacts de validation sous runs/tickets/TICKET-10/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

verify_assessment(...) -> VerificationResult ; decide_policy(inputs, config) -> PolicyDecision. Priorités et codes docs/decisions.md ; verdict/confiance argmax ; trois actions exactes.

## IMPLEMENTATION REQUIREMENTS

Partir des réponses vraiment collectées ; conserver copie invalidée pour audit et filtrer registre accepté. Les tests corrompent volontairement uniquement des copies isolées d’objets pour V01–V16 : ce sont attaques du validateur, pas réponses simulées du POC. Les résumés factuels seront rendus depuis le registre. Aucune promesse de détecter toutes contradictions libres.

## TESTS REQUIRED

Injection d’un ID/IOC, destinataire, provenance impossible, VT faux compteur, zéro VT bénin, CTI simple existence, chaîne URL inventée, screenshot absent, host partagé M, RAG interdit ; frontières 0.85/0.97/marge0.50 ; combinaison priorité critical vs verdict bénin ; fallback/null REVIEW.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_verify.py tests/test_policy.py -q
```

## EXPECTED RESULTS

Exit 0 ; chaque mutation structurée prévue est détectée ; aucun unsupported IOC accepté ; cas nominal réel ne reçoit pas d’alerte injustifiée de format.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Une assertion non fondée bloque AUTO ; tous les chemins policy ont des raisons auditables ; pas de dépendance réseau.

## FAIL CONDITIONS

Tests affaiblis, clés passées au LLM, M automatique par seul compteur, recipient conservé, score par défaut masquant échec.

## ARTEFACTS PRODUCED

Verifier/policy et matrice V01–V16→test.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-10 — Vérificateur et policy déterministes, gate G5. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
