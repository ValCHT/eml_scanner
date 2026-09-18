# CHANGELOG V1 → V1.1

18/09/2026 — delta ciblé de spécification ; aucune implémentation produit, aucun appel métier exécuté.

Les prompts INTERNAL/FINAL et les deux schemas JSON sont conservés octet pour octet. Les sept inspections research/ sont conservées ; aucune étude corpus relancée. Un processus, un StateGraph séquentiel, les règles R1/R2/R3, V01–V16 et la policy sont conservés.

FILE: `README.md`
SECTION: Version ; introduction ; prérequis des tickets
CHANGE: Version 1.1 et liens vers les deltas ; distinction G2/G6 ; VT indisponible non bloquant.
WHY: Rendre le point d’entrée cohérent avec les critères corrigés.
IMPACT ON TICKETS: 04, 06, 08, 14 ; aucune renumérotation.

FILE: `docs/architecture.md`
SECTION: Version ; §1.1, §1.4, §1.6
CHANGE: VT GET conservé, unavailable motivé autorise la suite ; audit du vrai payload INTERNAL référencé.
WHY: Supprimer le blocage VT sans fabriquer de couverture et détecter une entrée mal câblée.
IMPACT ON TICKETS: 04, 06, 08 ; signatures et graphe inchangés.

FILE: `docs/contracts.md`
SECTION: §2.6.1 ; §2.8
CHANGE: Audit par tentative : payload exact, deux hashes, quatre compteurs ; CallRecord existant conservé. GoldRecord ajoute raw_sha256, conserve email_sha256 avec égalité obligatoire ; métadonnées seules, champs de contenu interdits, résolution raw_path et contrôle des bytes avant analyse.
WHY: Vérifier ce qui atteint le transport Luna ; empêcher fuite de contenu dans les labels et dérive entre label et message évalué.
IMPACT ON TICKETS: 04, 13, 14 ; TICKET-01 reprend déjà les contrats normatifs sans changer son interface. Aucun schema de sortie ni prompt modifié.

FILE: `docs/prompt_integration.md`
SECTION: Après définition des enveloppes
CHANGE: Audit hors enveloppe ; conservation explicite des deux prompts V1 et du schema Assessment.
WHY: Éviter de modifier les prompts pour ajouter la télémétrie ou forcer les fixtures.
IMPACT ON TICKETS: 04 ; mêmes enveloppes et mêmes fonctions.

FILE: `docs/decisions.md`
SECTION: §4.1 uniquement
CHANGE: Seuils 0,90/0,20 nommés BASELINE V0 non calibrée ; pas de réglage avant G6, puis gold_dev uniquement ; métriques SIMPLE/COMPLEX obligatoires.
WHY: Mesurer les trois règles actuelles avant optimisation ; newsletter avec URL reste COMPLEX.
IMPACT ON TICKETS: 05, 14. §4.2 V01–V16 et §4.3 policy inchangés octet pour octet.

FILE: `docs/gates.md`
SECTION: §5.1 ; §5.1.1 ; §5.2
CHANGE: G2 technique sans justesse métier obligatoire, cinq checks anti-câblage, désaccords archivés ; G4 admet unavailable VT vérifié ; G6 valide gold sans contenu/hash ; G7-C précise son livrable et G7-D reste facultatif sans nouveau reçu.
WHY: Séparer implémentation et performance, permettre le POC sans VT, conserver le chemin de gates.
IMPACT ON TICKETS: 04, 06, 08, 13, 14, 17 ; ordre et dépendances conservés.

FILE: `docs/fixtures.md`
SECTION: Introduction
CHANGE: Labels attendus comparés mais non bloquants en G2 ; attentes de contenu transmis dans le manifest et bilan harness distinct du Gold.
WHY: Préserver les fixtures de sécurité/câblage sans entraîner les prompts à passer leurs labels.
IMPACT ON TICKETS: 03 inchangé : applique déjà docs/fixtures.md ; 04 modifié.

FILE: `docs/corpus.md`
SECTION: §7.5 uniquement
CHANGE: Gold Dev/Test explicitement limités aux métadonnées et labels ; contenu raw git-ignoré, vérification hash et aucun extrait en notes.
WHY: Appliquer la confidentialité aussi aux emails privés et lier chaque label aux bytes analysés.
IMPACT ON TICKETS: 13, 14 ; inspections et méthodologie de groupes/splits conservées.

FILE: `docs/evaluation.md`
SECTION: §8.1–§8.5
CHANGE: G6 première décision quantitative ; erreurs de fixtures séparées ; baseline V0 avant réglages ; qualité/coûts SIMPLE/COMPLEX ; A/B/C archivée et B−A/C−B distingués, coût expérimental B séparé du nominal. G7 reste facultatif ; G7-D sans ticket. Si fine-tuning YES : onze champs Phase 2 et candidat Qwen vérifié/documenté, sans sélection ni runtime.
WHY: Garantir une mesure interprétable du bundle, sans fuite de test, sans performance fabriquée ni conclusion de fine-tuning Luna.
IMPACT ON TICKETS: 14, 17 ; 15/16/18 gardent leurs interfaces. Coût B séparé pour ne pas attribuer au pipeline nominal le coût de son contrôle expérimental.

FILE: `tickets/TICKET-04.md`
SECTION: OBJECTIF ; IMPLEMENTATION REQUIREMENTS ; TESTS REQUIRED ; EXPECTED RESULTS ; ACCEPTANCE CRITERIA ; FAIL CONDITIONS ; ARTEFACTS PRODUCED
CHANGE: Retire les assertions de bons labels ; impose audit exact, contenu attendu, structured output réel, rejets explicites et conservation des désaccords.
WHY: Un payload correct et un mauvais classement doivent pouvoir PASS G2 ; un payload vide ne le peut pas.
IMPACT ON TICKETS: 04 modifié ; dépendance G1 et fonctions conservées.

FILE: `tickets/TICKET-05.md`
SECTION: IMPLEMENTATION REQUIREMENTS
CHANGE: Nomme BASELINE V0 et reporte toute calibration après première mesure G6 sur dev.
WHY: Éviter une optimisation prématurée sans changer R1/R2/R3.
IMPACT ON TICKETS: 05 modifié ; aucun nouveau contrôle du vérificateur.

FILE: `tickets/TICKET-06.md`
SECTION: PRECONDITIONS ; IMPLEMENTATION REQUIREMENTS ; TESTS REQUIRED ; VALIDATION COMMANDS ; EXPECTED RESULTS ; ACCEPTANCE CRITERIA ; ARTEFACTS PRODUCED
CHANGE: Clé/droits non prérequis de construction ; unavailable motivé admis pour DONE ; smoke --if-configured ; branches d’erreurs testables localement, jamais de résultat VT fictif en métriques.
WHY: VT indisponible ne doit pas bloquer la suite du POC.
IMPACT ON TICKETS: 06 modifié ; 07 reste exécutable après DONE 06 sans accès VT.

FILE: `tickets/TICKET-08.md`
SECTION: EXPECTED RESULTS
CHANGE: Fermeture G4 avec CTI/urlscan réellement validés et VT réel ou unavailable vérifié ; explicite la sémantique de --require-all.
WHY: Éliminer le blocage VT résiduel à la fermeture des enrichissements.
IMPACT ON TICKETS: 08 modifié ; aucune modification de signature ou commande globale.

FILE: `tickets/TICKET-13.md`
SECTION: IMPLEMENTATION REQUIREMENTS ; TESTS REQUIRED ; FAIL CONDITIONS
CHANGE: Contrat gold métadonnées seules, raw_sha256 et raw_path ; refus de contenu, chemin invalide et mismatch ; contrôles de build sans lecture du test.
WHY: Confidentialité Golden et intégrité des données avant mesure.
IMPACT ON TICKETS: 13 modifié ; 12 et procédure de scellement conservés.

FILE: `tickets/TICKET-14.md`
SECTION: PRECONDITIONS ; IMPLEMENTATION REQUIREMENTS ; TESTS REQUIRED
CHANGE: VT non bloquant, validation gold, six métriques de chemins, baseline V0, bilan fixtures distinct, A/B/C exécutée par la commande baseline, G7-D hors PASS.
WHY: G6 mesure vraiment la qualité et la contribution du bundle sans confondre les effets.
IMPACT ON TICKETS: 14 modifié ; signature evaluate et CLI baseline/recompute conservées.

FILE: `tickets/TICKET-17.md`
SECTION: IN SCOPE ; INTERFACES / CONTRACTS ; IMPLEMENTATION REQUIREMENTS ; TESTS REQUIRED
CHANGE: Onze champs si YES ; Qwen3.8-27B candidat Phase 2 sourcé ; besoin/faisabilité/bénéfice séparés, aucun entraînement/runtime/dépendance.
WHY: Rendre une éventuelle suite exploitable sans choisir un modèle sans benchmark.
IMPACT ON TICKETS: 17 modifié ; aucun ticket créé/splitté.

FILE: `SOC_Email_Triage_POC_Plan_17092026.md`
SECTION: En-tête et sections correspondant aux fichiers modifiés
CHANGE: Synchronisation exacte des composants corrigés dans le plan consolidé existant ; export TXT identique.
WHY: Éviter une seconde vérité normative dans le livrable V1 existant.
IMPACT ON TICKETS: Même liste de 18 tickets ; aucun nouveau ticket.

FILE: `QA.md`
SECTION: Vérification finale V1.1
CHANGE: Consigne la revue unique de cohérence, ses éventuels blockers corrigés et le statut de gel, distinct des gates runtime NOT_STARTED.
WHY: Tracer la vérification demandée sans nouvelle gate ni framework.
IMPACT ON TICKETS: Aucun ticket exécuté ; TICKET-01 demeure la prochaine étape d’implémentation.

FILE: `SHA256SUMS.json`
SECTION: Manifest entier
CHANGE: Empreintes recalculées des fichiers finaux, changelog et matrice inclus.
WHY: Garantir l’intégrité de l’archive corrigée.
IMPACT ON TICKETS: Aucun impact fonctionnel.

FILE: `CHANGELOG_V1_TO_V1.1.md` ; `TICKET_MATRIX_V1_TO_V1.1.md`
SECTION: Fichiers de livraison demandés
CHANGE: Deux documents ajoutés pour expliquer les deltas et identifier les tickets conservés/modifiés.
WHY: Rendre la V1.1 révisable sans doublons de spécification ni nouveau processus.
IMPACT ON TICKETS: Aucun ticket supplémentaire ; 18 tickets conservés.

Changements de prompts : **aucun**. Aucun téléchargement Qwen, runtime alternatif, entraînement, nouvelle base ou nouveau framework. La compatibilité PEFT/QLoRA est une appréciation de faisabilité architecturale, non un essai réalisé sur ce POC ; validation de la stack et benchmark réservés à la Phase 2.

FILE: `tickets/TICKET-17.md` ; `docs/gates.md`
SECTION: VALIDATION COMMANDS / EXPECTED RESULTS / ARTEFACTS PRODUCED ; §5.2
CHANGE: Correction Astra : ajout de `python scripts/check_gate.py G7-C --record`, des contrôles de clôture fixes et du reçu `runs/gates/G7-C/gate.json` si G7-C est menée ; correction validée lors de la revue GPT-5.6 Sol effective du 18/09/2026.
WHY: BLOCKER SOL-01 : la V1 ne donnait pas de clôture archivée G7-C permettant à TICKET-18 de vérifier cette dépendance. Correction limitée à l’exécutabilité de la chaîne, sans nouvelle gate.
IMPACT ON TICKETS: 17 seulement ; 18 inchangé consomme le reçu ou la décision explicite de ne pas mener l’option. Aucun ticket lancé.

Revue GPT-5.6 Sol effective : 18/09/2026. SOL-01 validé fermé ; SOL-02 identifié puis corrigé (minimisation des payloads INTERNAL hors fixtures). 0 blocker restant, 0 follow-up. Aucun changement stylistique ou réarchitectural ajouté.

FILE: `docs/contracts.md` ; `docs/architecture.md` ; `docs/gates.md` ; `tickets/TICKET-04.md`
SECTION: Audit des entrées INTERNAL / G2
CHANGE: Le payload HTTP exact n'est persisté que pour les fixtures G2. Pour `public_corpus` et `private_authorized`, les hashes et compteurs sont calculés sur les mêmes bytes en mémoire que ceux transmis, sans écrire le request body complet sur disque.
WHY: BLOCKER SOL-02 : éviter une copie persistante supplémentaire d'emails corpus/privés tout en conservant la preuve déterministe de câblage.
IMPACT ON TICKETS: TICKET-04 uniquement ; interfaces, prompts, schemas et critères métier inchangés.

FILE: `QA.md` ; `CHANGELOG_V1_TO_V1.1.md`
SECTION: Provenance de revue
CHANGE: La mention d'une revue Sol antérieure non traçable est remplacée par la présente revue GPT-5.6 Sol effective. SOL-01 est conservé comme correction Astra validée ; SOL-02 est ajouté et fermé.
WHY: Assurer une provenance exacte des contrôles de revue.
IMPACT ON TICKETS: Aucun.

**V1.1 READY FOR IMPLEMENTATION: YES**

## Fichiers effectivement modifiés

- `QA.md`
- `README.md`
- `SHA256SUMS.json`
- `SOC_Email_Triage_POC_Plan_17092026.md`
- `docs/architecture.md`
- `docs/contracts.md`
- `docs/corpus.md`
- `docs/decisions.md`
- `docs/evaluation.md`
- `docs/fixtures.md`
- `docs/gates.md`
- `docs/prompt_integration.md`
- `tickets/TICKET-04.md`
- `tickets/TICKET-05.md`
- `tickets/TICKET-06.md`
- `tickets/TICKET-08.md`
- `tickets/TICKET-13.md`
- `tickets/TICKET-14.md`
- `tickets/TICKET-17.md`
- `TICKET_MATRIX_V1_TO_V1.1.md`

Ajoutés : `CHANGELOG_V1_TO_V1.1.md`, `TICKET_MATRIX_V1_TO_V1.1.md`.

Le TXT joint est l’export identique du plan consolidé existant, mis à jour au même titre. Les autres fichiers V1 sont conservés octet pour octet.
