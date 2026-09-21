# TICKET-16 — Vision et QR sans second pipeline

## GATE

G7-B

## AMENDEMENT OPÉRATEUR (2026-09-21) — smoke visuel borné uniquement

Aucun benchmark complet avant TICKET-19 : T16 exécute un **smoke visuel borné uniquement** — préférer le subset visual-essential (`essential_visual_content`) une fois matérialisé, sinon le smoke dev T14 ; jamais le run complet Visual-79 avant T19. Sortie sous `runs/eval/dev_vision_smoke`. Les métriques restent diagnostiques (`performance_claims_allowed=false`) ; INCONCLUSIVE est un résultat valide. Le premier benchmark complet (texte seul / texte+QR / texte+QR+vision sur les cas visuels) est T19.

## OBJECTIF

Mesurer l’apport des images et du décodage QR.

## PRECONDITIONS / DÉPENDANCES

PASS G6 ; capacité vision réellement démontrable sur le proxy ; corpus visuel validé ; G7-A terminée ou explicitement non retenue.

## IN SCOPE

Vision sur mêmes appels Luna, QR local, protection taille/décode, screenshots urlscan réels.

## OUT OF SCOPE

Pipeline OCR distinct, visite locale d'URL, deuxième modèle, vision obligatoire pour la baseline, contenu d'image inventé.

## FILES ALLOWED

src/parsing.py; src/llm.py; src/tools/urlscan.py; src/prompts.py; tests/test_vision.py; scripts/smoke.py; configs/tools.yaml; configs/experiment_lock.json; docs/contracts.md; docs/evaluation.md; pyproject.toml; requirements.lock. Artefacts de validation sous runs/tickets/TICKET-16/ et runs/gates/ de la gate concernée.

## INTERFACES / CONTRACTS

prepare_visuals(parsed, limits) -> list[VisualEvidence] ; decode_qr(image_bytes: bytes) -> list[str]. Mêmes fonctions assess_internal/final, message utilisateur multipart avec data URI. Payload QR validée ajoutée au registre comme INTERNE avant le même gate et les mêmes règles de sortie.

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
