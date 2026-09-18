# SOC Email Triage — dossier d'architecture et tickets Codex

Version 1.2 — 18/09/2026 — spécification, sans implémentation applicative.

**Un processus Python, un graphe séquentiel, de vrais appels Luna et fournisseurs, un RAG exclusivement public et facultatif.** Ce dossier tient compte des deux précisions : aucune réponse d'analyse/enrichissement simulée ; aucune donnée privée dans le RAG.

Lire le plan consolidé pour la vue complète. Le dossier contient aussi les documents séparés, deux prompts complets, deux schemas JSON autonomes et 18 tickets directement utilisables comme prompts Codex.

Delta et gel : historique [V1 → V1.1](CHANGELOG_V1_TO_V1.1.md) / [matrice](TICKET_MATRIX_V1_TO_V1.1.md), puis micro-patch [V1.1 → V1.2](CHANGELOG_V1.1_TO_V1.2.md) / [matrice](TICKET_MATRIX_V1.1_TO_V1.2.md), et [vérification finale](QA.md). G2 valide le harness et ses entrées ; G3 ne dépend plus d'un SIMPLE live stochastique ; G6 porte la première décision quantitative de qualité et audite les variantes FINAL B/C. Aucun ticket n'est exécuté par cette révision de spécification.

## Ordre de lecture

1. [Architecture et StateGraph](docs/architecture.md)
2. [État, contrats et configuration](docs/contracts.md)
3. [Intégration des prompts](docs/prompt_integration.md), [internal](prompts/internal_assessment.txt), [final](prompts/final_assessment.txt)
4. [Complexity gate, verifier et policy](docs/decisions.md)
5. [Gates G0–G7 et invocation](docs/gates.md)
6. [Fixtures](docs/fixtures.md), [corpus et RAG public](docs/corpus.md), [évaluation](docs/evaluation.md)

## Ordre des tickets

| Ticket | Gate | Résultat |
|---|---|---|
| [01](tickets/TICKET-01.md) | G0 | Squelette, Settings et contrats |
| [02](tickets/TICKET-02.md) | G0 | Client Luna réel et bootstrap PASS |
| [03](tickets/TICKET-03.md) | G1 | Parser et 14 fixtures |
| [04](tickets/TICKET-04.md) | G2 | Baseline internal réelle |
| [05](tickets/TICKET-05.md) | G3 | Complexity gate à trois règles |
| [06](tickets/TICKET-06.md) | G4 | VT réel, sans upload |
| [07](tickets/TICKET-07.md) | G4 | OpenCTI réel en lecture seule |
| [08](tickets/TICKET-08.md) | G4 | urlscan privé réel et PASS enrichissements |
| [09](tickets/TICKET-09.md) | G5 | Evidence merge et final réel |
| [10](tickets/TICKET-10.md) | G5 | Vérificateur et policy |
| [11](tickets/TICKET-11.md) | G5 | Graphe, CLI, rapports et batch |
| [12](tickets/TICKET-12.md) | G6 | Inspection/normalisation corpus |
| [13](tickets/TICKET-13.md) | G6 | Labels revus, groupes, test scellé |
| [14](tickets/TICKET-14.md) | G6 | Mesure baseline dev et protocole reproductible |
| [15](tickets/TICKET-15.md) | G7-A | Expérience RAG public |
| [16](tickets/TICKET-16.md) | G7-B | Expérience vision/QR |
| [17](tickets/TICKET-17.md) | G7-C | Décision fine-tuning sans entraînement |
| [18](tickets/TICKET-18.md) | Clôture mesure G6 | Évaluation test terminale après gel |

Le ticket 13 exige des annotations humaines déjà confirmées et un responsable du holdout. Les appels d'intégration utilisent de vrais accès autorisés ; une indisponibilité VT explicite ne bloque ni TICKET-06 DONE, ni G4/G5/G6. Ces prérequis ne sont jamais remplacés par des données ou résultats inventés.

## Mise à disposition dans le futur repo

Créer un répertoire de travail `soc-email-triage` ; copier ce dossier docs/ dans docs/, prompts/ et schemas/ à la racine, puis tickets/ vers docs/tickets/. Ne pas copier research/ dans les inputs Luna. Lancer TICKET-01 selon la commande PowerShell/Bash de docs/gates.md. Chaque fichier ticket entier est un prompt autonome, avec prérequis, fichiers autorisés, contrats, tests, commandes, résultats attendus et conditions de blocage. Aucun composant src/ n'est livré ici : l'implémentation commence seulement à l'exécution des tickets.

## Contrats livrés

- [Schema de sortie Luna](schemas/assessment.schema.json)
- [Schema du rapport](schemas/triage_report.schema.json)

Les schemas ont été vérifiés syntaxiquement et leurs références sont locales. Cela ne vaut pas acceptation du sous-ensemble par le proxy Orange : son test réel reste exigé en G0/G2. Aucun accès privé/API key n'a été utilisé pour produire ce plan. Les capacités spécifiques du proxy, autorisations VT et disponibilités live restent à vérifier lors de l'implémentation.

## Inspection publique déjà réalisée

Sept comptes rendus dans research/ : trois archives SpamAssassin complètes, les deux JSON PhishFuzzer complets, la mailbox Nazario 2025 complète et les 50 premiers messages Enron. Méthode, empreintes et limites dans docs/corpus.md. IWSPA a été étudié dans sa publication et sa page officielle ; son archive n'a pas été inspectée. Aucun corpus privé consulté. Aucun résultat de classification produit ou prétendu.

Le RAG initial proposé contient environ 150 cas publics distincts du Golden, issus principalement de Nazario 2025 et SpamAssassin. Leur labellisation selon les six classes devra être confirmée ; les inspections présentes n'en tiennent pas lieu.
