# TICKET-06 — VirusTotal : lookup réel sans upload

## GATE

G4

## OBJECTIF

Valider VT sur les seuls lookups autorisés.

## PRECONDITIONS / DÉPENDANCES

PASS G3. Clé, autorisation VT et hash public approuvé nécessaires uniquement pour les appels live possibles ; leur absence n’empêche pas l’implémentation ni TICKET-06 DONE.

## IN SCOPE

vt-py, hash/URL/domain/IP, normalisation, quotas/délais, confidentialité et collecte réelle.

## OUT OF SCOPE

POST/scan/upload/download fichier ; contournement des quotas ; recours à une fausse API pour PASS.

## FILES ALLOWED

src/tools/__init__.py; src/tools/virustotal.py; configs/tools.yaml; tests/test_virustotal.py; scripts/smoke.py; docs/contracts.md; docs/threat_model.md. Artefacts de validation sous runs/tickets/TICKET-06/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

VirusTotalAdapter.lookup(query: Observable, context: ToolContext) -> ToolResult ; URL id via vt.url_id ; evidence atomique OSINT avec pointer vers réponse ; champs absents null ; formats exacts schemas/triage_report.schema.json.

## IMPLEMENTATION REQUIREMENTS

Quatre types GET uniquement. SHA-256 prioritaire, pas trois hashes du même fichier. Local rate limiter et journal quota JSON, pas d’attente sur 429. Budget phase20 s. Clé hors contexte/log. Sans clé/droits : unavailable/not_configured ou access_not_authorized et zéro requête. Refus, panne, timeout ou 429 : unavailable avec cause, puis suite OpenCTI→urlscan→FINAL. La gestion vérifiée de cette indisponibilité permet DONE et G4 PASS ; vt_nominal_validated=false dans couverture/limites si aucun nominal réel. Aucun faux résultat ni système mock/test/real supplémentaire.

## TESTS REQUIRED

Si accès disponible, succès connu et hash inconnu réels, chaque endpoint activé et captures authentiques. Sinon tester le vrai adaptateur sans clé/droits et son unavailable explicite ; ne pas marquer le test obligatoire skipped. Tester les branches timeout/refus/429 sur objets d’erreur contrôlés au normaliseur, sans résultat VT fictif dans le pipeline ou les métriques. Contrôler limites locales, champs absents et interdiction des POST ; disponibilité nominale réellement observée distincte du traitement local des erreurs.

## VALIDATION COMMANDS

```bash
python scripts/check_gate.py G3
python -m pytest tests/test_virustotal.py --live -q
python scripts/smoke.py virustotal --if-configured
```

## EXPECTED RESULTS

Exit 0 si l’adaptateur produit un résultat réel ou unavailable avec cause et invariants respectés ; aucune requête POST. Sans nominal disponible, DONE avec couverture nominale non validée explicite, jamais faux succès. Un bug, une cause absente ou une divulgation restent FAIL.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Adaptateur présent et traitement d’indisponibilité vérifié ; appels réels dès que permis. Aucun champ de réputation présenté comme certitude ; accès utilisé uniquement si autorisé. L’indisponibilité VT ne bloque pas les tickets suivants.

## FAIL CONDITIONS

API gratuite présumée autorisée malgré restriction, upload, faux succès, secret exposé, 0 détection transformé en bénin.

## ARTEFACTS PRODUCED

Adaptateur, résultat du smoke, causes/coverage et éventuelles captures live sous runs/gates/G4/virustotal/ ; ticket 06 DONE même avec unavailable vérifié, G4 pas encore PASS avant 07–08.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-06 — VirusTotal : lookup réel sans upload, gate G4. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
