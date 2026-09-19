# TICKET-08 — urlscan réel et clôture enrichissements

## GATE

G4

## AMENDEMENT OPÉRATEUR (19/09/2026)

Décisions explicitement fournies par l'opérateur pour lever le BLOCKED initial :

- **URLs autorisées** (publiques, bénignes, sans credential ni donnée personnelle) :
  - `LIVE_BENIGN_URL=https://httpbin.org/html`
  - `LIVE_REDIRECT_URL=https://httpbin.org/redirect-to?url=https%3A%2F%2Fhttpbin.org%2Fhtml&status_code=302`
  Ces URLs exactes sont autorisées pour la soumission réelle à urlscan dans le cadre de cette validation POC.
- **Egress** : l'absence d'approbation persistante dans `configs/tools.yaml` n'est pas un blocage. Le dépôt reste safe-by-default (`allow_real_urls=false`, `approved_services=[]`, `approved_exact_url_hosts=[]`) ; les contextes officiels live/smoke de TICKET-08 construisent un `EgressConfig` temporaire explicite (`allow_real_urls=true`, service `urlscan`, hôte exact `httpbin.org`). Aucune whitelist globale.
- **Visibilité (autoritative par `source_profile`)** : `fixture` → `unlisted`, `public_corpus` → `unlisted`, `private_authorized` → `private`. Jamais `public`, jamais de fallback. `configs/tools.yaml` devient `visibility_fixture: unlisted` ; `visibility_real` reste `private` (un `public_corpus` ne devient jamais `private` par ce champ).
- **VirusTotal** : `VT_ACCESS_AUTHORIZED=false` est intentionnel et autorisé ; VT doit produire son `unavailable` contrôlé explicite avec `vt_nominal_validated=false`. G4 reste atteignable ; la validation urlscan publique en `unlisted` (profil fixture) et la validation OpenCTI réelle restent obligatoires.

## OBJECTIF

Observer réellement une page et sa redirection avec confidentialité.

## PRECONDITIONS / DÉPENDANCES

Tickets 06–07 DONE ; clé urlscan avec quota private ; URL bénigne et URL à redirection bénigne autorisées.

## IN SCOPE

Préfiltre URLs, POST private, poll, résultat normalisé, DOM inerte ; référence screenshot préparée pour G7.

## OUT OF SCOPE

Soumission de credentials, lien dangereux ouvert localement, public, downgrade de visibilité, fausse chaîne de redirection.

## FILES ALLOWED

src/tools/urlscan.py; configs/tools.yaml; tests/test_urlscan.py; scripts/smoke.py; docs/contracts.md; docs/threat_model.md; tests/test_contracts.py. Artefacts de validation sous runs/tickets/TICKET-08/ et runs/gates/ de la gate concernée.

Limitation explicite pour `tests/test_contracts.py` : « only the existing exact visibility_fixture contract assertion may be aligned with the operator-approved private -> unlisted change. No other G0 contract may be modified. »

## INTERFACES / CONTRACTS

UrlscanAdapter.scan(query, context) -> ToolResult. Une URL/email. UUID validé ; phase≤45 s ; 404 pending, 410 supprimé ; pointeurs de source et evidence SANDBOX. Capture binaire screenshot uniquement G7 actif.

## IMPLEMENTATION REQUIREMENTS

Préfiltre privé/secrets/side effects ; visibility explicitement envoyée et vérifiée dans réponse (mapping autoritatif par `source_profile`, amendement opérateur). Pas de seconde soumission après POST ambigu. Attente10 s puis poll5 s jusqu’à budget. DOM rendu texte sans JS ; ne pas confondre sous-ressources et navigation principale. Les domaines `.test` restent skipped. Smoke utilise un vrai site de test bénin ; aucun résultat malveillant inventé.

## TESTS REQUIRED

Scan live privé réel, redirection live bénigne vérifiable, pending naturel, disparition/délais, refus quota local et test du parseur 429 sur archive réelle si existante ; URL credential/private host refusée avant réseau ; screenshot absent ne casse pas JSON. Intégration tous outils réelle, erreurs vers unavailable.

## VALIDATION COMMANDS

```bash
python -m pytest tests/test_urlscan.py --live -q
python scripts/smoke.py tools --require-all
python scripts/check_gate.py G4 --record
```

## EXPECTED RESULTS

Exit 0 ; scans réels private (pytest) et unlisted public-fixture (smoke), observations exactes, capture de redirection ; preuves nominales CTI/urlscan présentes ; VT réel si disponible, sinon unavailable avec cause et gestion vérifiée, couverture nominale non validée explicite. Le smoke --require-all applique cette règle de docs/gates.md sans nouveau mode. VT indisponible ne bloque pas G4 ; CTI/urlscan gardent les prérequis V1.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

G4 PASS ; aucun outil ne laisse une exception attendue faire tomber le pipeline ; états d’absence et de blocage différenciés.

## FAIL CONDITIONS

Fallback unlisted/public, envoi URL sensible, credentials soumis, screenshot ou result forgé, clé transmise à un autre origin.

## ARTEFACTS PRODUCED

Adaptateur urlscan, smoke intégré réel et receipt G4.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-08 — urlscan réel et clôture enrichissements, gate G4. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
