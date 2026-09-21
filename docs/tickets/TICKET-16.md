# TICKET-16 — Vision et QR sans second pipeline

## GATE

G7-B

## AMENDEMENT OPÉRATEUR (2026-09-21, trajectoire accélérée) — développement parallèle, smoke visuel borné

Aucun benchmark complet avant T19E : T16 exécute un **smoke visuel borné uniquement** — préférer le subset visual-essential (`essential_visual_content`) une fois matérialisé, sinon le smoke dev T14 ; jamais le run complet Visual-79 avant T19E. Le développement de T16 est **parallèle à T15 et à la chaîne T19A→T19B** (indépendant du RAG, de l'agentique et de G7-A) ; la fermeture expérimentale G7-B peut être enregistrée plus tard. Sortie sous `runs/eval/dev_vision_smoke`. Les métriques restent diagnostiques (`performance_claims_allowed=false`) ; INCONCLUSIVE est un résultat valide. Les résultats alimentent T19C ; le premier benchmark complet (texte seul / texte+QR / texte+QR+vision sur les cas visuels, rerun simultané de la V1 fixe) est T19E.

## OBJECTIF

Mesurer l’apport des images et du décodage QR.

## PRECONDITIONS / DÉPENDANCES

Développement autorisé en parallèle de T15 et T19A/B, indépendant de G7-A ; la fermeture expérimentale G7-B peut attendre l'état G6/synchronisation approprié ; capacité vision réellement démontrable sur le proxy ; corpus visuel validé ; décision explicite de lancer l'expérience optionnelle.

## IN SCOPE

Vision sur mêmes appels Luna, QR local, protection taille/décode, screenshots urlscan réels.

## OUT OF SCOPE

Pipeline OCR distinct, visite locale d'URL, deuxième modèle, vision obligatoire pour la baseline, contenu d'image inventé.

## FILES ALLOWED

src/parsing.py; src/llm.py; src/tools/urlscan.py; src/prompts.py; scripts/smoke.py; scripts/evaluate.py; src/metrics.py; tests/test_vision.py; tests/test_metrics.py; tests/test_evaluation.py; configs/tools.yaml; configs/experiment_lock.json; docs/contracts.md; docs/evaluation.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-16/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

prepare_visuals(parsed, limits) -> list[VisualEvidence] ; decode_qr(image_bytes: bytes) -> list[str]. Mêmes fonctions assess_internal/final, message utilisateur multipart avec data URI. Payload QR validée ajoutée au registre comme INTERNE avant le même gate et les mêmes règles de sortie.

**Interface évaluateur appariée (review PR #15, 2026-09-21) — implémentée par ce ticket.** `scripts/evaluate.py` doit accepter `--variant vision` et `--paired-with <run-dir>` pour un run `--sample-profile smoke` :
- le run apparié est un run baseline archivé (`runs/eval/dev_smoke`) : il est LU seul, jamais rejoué, et ses lignes/reports ne sont jamais modifiés ;
- la comparaison apparie exactement les mêmes `sample_id` (identité de sélection vérifiée) et exige des dénominateurs identiques ; une ligne manquante ou surnuméraire = FAIL ;
- `measurement_scope=smoke` et `performance_claims_allowed=false` restent archivés ; les métriques restent diagnostiques, INCONCLUSIVE valide ;
- aucun tuning sur les résultats ; les résultats alimentent T19C ; le premier benchmark complet texte/QR/vision sur les cas visuels est T19E.

## IMPLEMENTATION REQUIREMENTS

Pillow et zxing-cpp seulement dans extra vision. PNG/JPEG, 4 images au maximum, 4 MiB par image, 16 millions de pixels décodés, 8 MiB envoyés au total. Tracer l’empreinte de l’original et celle de toute image dérivée. Pas de SVG/animation ni d’image distante. Payload QR non URL conservée comme texte. Décodage avant gate. Flag désactivé : métadonnées seulement, REVIEW si le contenu visuel est essentiel. Screenshot réel de provenance SANDBOX, image email INTERNE, interprétation INFERENCE.

## TESTS REQUIRED

Smoke visuel réel sur image bénigne ; payload QR exacte ; image-only ; injection visuelle ; image corrompue et limites de décodage ; flag désactivé sans dépendances optionnelles ; screenshot absent ; fallback texte explicite si proxy rejette vision. Ablation réelle texte/texte+QR/texte+QR+vision sur les mêmes cas.

## VALIDATION COMMANDS

```bash
python -m pip install -e ".[dev,vision]"
python scripts/smoke.py vision --require-configured
python -m pytest tests/test_vision.py --live -q
python scripts/evaluate.py --split dev --mode live --variant vision --sample-profile smoke --paired-with runs/eval/dev_smoke --out runs/eval/dev_vision_smoke
python scripts/check_gate.py G7-B --record
```

## EXPECTED RESULTS

Exit 0 ; images effectivement transmises et payloads réellement décodées ; aucun scan local ni formulaire soumis ; limites respectées ; métriques ou INCONCLUSIVE si le subset est insuffisant.

## SECURITY INVARIANTS

Aucune réponse Luna/VT/OpenCTI/urlscan simulée. Fixtures = données d’entrée seulement. Aucun secret dans code, prompts, état ou logs ; aucune pièce jointe exécutée/uploadée ; aucun accès Internet libre au LLM ; tiers via adaptateurs typés et règles de sortie ; RAG exclusivement public, validé et disjoint de gold ; test non accessible aux agents de build.

## ACCEPTANCE CRITERIA

Capacité vision validée sur le vrai proxy et utilité mesurée ; baseline toujours fonctionnelle ; test fermé.

## FAIL CONDITIONS

Description de pixels absents ; visite directe d’une URL QR ; IOC perçu mais non validé ajouté au registre ; dépendance optionnelle imposée en mode texte ; faux screenshot.

## ARTEFACTS PRODUCED

Extension facultative vision/QR, réponses réelles, comparaison et décision.

## CODEX EXECUTION PROMPT

Exécute uniquement TICKET-16 — Vision et QR sans second pipeline, gate G7-B. Le présent fichier complet est ton prompt autonome. Lis AGENTS.md s’il existe, puis docs/architecture.md, docs/contracts.md, docs/decisions.md, docs/gates.md et les documents de domaine cités ici. Vérifie les préconditions ci-dessus, implémente exactement le périmètre dans FILES ALLOWED, lance toutes les commandes VALIDATION COMMANDS et conserve les preuves réelles. Si un prérequis est absent, rends BLOCKED avec le fichier/capacité manquant ; ne le remplace pas par une hypothèse, un skipped ou une simulation. Corrige les échecs sans abaisser les tests. Termine par les fichiers changés, commandes et résultats effectifs, artefacts, statut du ticket et statut de la gate. Ne commence aucun autre ticket. Aucun accès à un échange antérieur avec l’utilisateur n’est nécessaire.
