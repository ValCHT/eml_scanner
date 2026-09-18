# TICKET-04 — Internal Assessment avec Luna réel

## GATE

G2

## OBJECTIF

Valider techniquement INTERNAL email-only et son câblage vers Luna, sans critère de justesse métier en G2.

## PRECONDITIONS / DÉPENDANCES

PASS G1 ; clé Luna fonctionnelle et contrat réel du proxy validé.

## IN SCOPE

Prompt internal, projection de données, schema métier, validation des IDs/probas, commande d’analyse interne et captures live.

## OUT OF SCOPE

VT/OpenCTI/urlscan/RAG ; classification simulée ; verdict final enrichi ; vision active.

## FILES ALLOWED

src/prompts.py; src/llm.py; src/verify.py; tests/test_internal.py; tests/test_llm_client.py; scripts/smoke.py; scripts/validate_reports.py; docs/prompt_integration.md; prompts/internal_assessment.txt. Artefacts de validation sous runs/tickets/TICKET-04/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

assess_internal(parsed: ParsedEmail, client: LunaClient, limits: ContextLimits) -> (Assessment | None, CallRecord). validate_assessment_shape_and_refs(assessment, registry, phase) retourne issues. Calculer label/score depuis p, sans normaliser les p invalides.

## IMPLEMENTATION REQUIREMENTS

Charger le prompt complet livré. Enlever labels/chemins de dataset et anciennes décisions X-Spam de la projection, conserver raw. Appel medium sans tools, max deux tentatives dans 60 s. Pour les fixtures G2, archiver chaque réponse/erreur réelle, validité première tentative, les bytes réellement remis au transport et les six champs d'audit de docs/contracts.md §2.6.1. Le mécanisme d'audit doit aussi supporter `public_corpus` et `private_authorized` sans persister le payload HTTP complet : hashes/compteurs calculés en mémoire sur les mêmes bytes que ceux transmis. Même enveloppe, mêmes signatures et schemas. Prompt livré inchangé sauf incohérence concrète documentée ; aucun tuning pour faire passer une fixture. Injections HTML traitées comme données. Si aucune capacité disponible, BLOCKED, jamais faux verdict.

## TESTS REQUIRED

Vrais appels sur les fixtures : six probabilités valides, schema strict et IDs existants pour toute sortie acceptée, aucune evidence externe ; comparer les labels attendus sans assert de justesse. Checks anti-câblage bloquants de docs/gates.md §5.1.1 : contenu utile attendu, pas d’enveloppe vide/substituée, fingerprints distincts si contenu distinct, hashes/compteurs recalculables depuis les mêmes bytes envoyés ; réponse complète identique → diagnostic, même verdict seul → aucune erreur technique. Les attentes d’entrée viennent du manifest ; malformed et images non lues conservent les lacunes. Références/probas invalides sont testées comme entrées du validateur. Absence de secret et de nom de fixture dans payload. Au moins deux runs des cas injection/auth PASS ; variations mesurées, pas cachées.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G1
python scripts/smoke.py luna --require-configured
python -m pytest tests/test_internal.py --live -q
python scripts/validate_reports.py --assessments runs/gates/G2/assessments.jsonl
python scripts/check_gate.py G2 --record
```

## EXPECTED RESULTS

Exit 0 aux commandes ; au moins un succès métier structuré réel prouve le contrat complet ; toutes sorties acceptées valides, autres tentatives rejetées/archivées comme erreurs/refus/timeouts. Toutes entrées attendues vérifiées et captures authentiques présentes. Un phishing classé spam avec entrée/contrat corrects peut PASS G2 ; désaccord conservé pour le bilan G6 séparé du Gold.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Exécution réelle et entrée correcte sur toutes fixtures parsables ; zéro référence inconnue acceptée ; aucune instruction de fixture exécutée ; l’absence d’image ne devient pas une description visuelle. G2 ne mesure pas un seuil de performance métier.

## FAIL CONDITIONS

Repli simulé, prompts réduits pour contourner injection, sortie déclarée valide sans contrôle, clé absente, schema/taxonomie de sortie non respectés sans rejet explicite, contenu attendu absent/substitué, hash non reproductible. Un mauvais label parmi les six classes n’est pas une fail condition.

## ARTEFACTS PRODUCED

Prompt internal V1 conservé, pipeline interne, tests live, requests exactes uniquement pour fixtures G2, audits/réponses/erreurs par tentative et archive G2, dont fixture_performance.jsonl pour les désaccords non bloquants. Pour corpus/privé, aucun request body complet persisté.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-04 — Internal Assessment avec Luna réel, gate G2. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
