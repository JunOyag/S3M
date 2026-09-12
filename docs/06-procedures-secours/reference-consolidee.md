---
id: secours.reference-consolidee
kind: narrative
title: "Procédures de Secours — Référence Consolidée"
section: "§6"
status: draft
verified_by: []
---

# Procédures de Secours — Référence Consolidée

Point d'entrée unique vers les mécanismes de reconstruction, migration et
gestion des compromissions, détaillés chacun sur leur propre page. **Cette
page ne contient aucune description de mécanisme** — uniquement des liens —
pour qu'une mise à jour d'une procédure n'ait jamais à être répercutée ici
en plus de sa page d'origine.

| Scénario déclencheur | Procédure | Réversible ? |
|---|---|---|
| Nœud temporairement indisponible | [`protocols.write-queue`](../04-protocols/write-queue.md) | Oui, au retour du Nœud |
| Nœud seul injoignable, réseau disponible | [`protocols.espace-secours`](../04-protocols/espace-secours.md) | Oui, réintégration automatique |
| Bloc corrompu détecté | [`protocols.integrite-lecture`](../04-protocols/integrite-lecture.md) | Oui si reconstruction possible |
| Partenaire hors-ligne (timeout) | [`protocols.volatilite-reparation`](../04-protocols/volatilite-reparation.md) | Oui, automatique |
| Partenaire fraudeur (PoS incorrect) | [`securite.blacklist-fraude`](../05-securite/blacklist-fraude.md) | Non — blacklist permanente |
| Changement de Nœud volontaire | [`protocols.migration-noeud`](../04-protocols/migration-noeud.md) | Oui |
| Nœud définitivement perdu | [`protocols.migration-noeud`](../04-protocols/migration-noeud.md) *(même procédure)* | Oui, tant que les partenaires répondent |
| Compromission clé User | [`crypto.master-key-chain`](../03-crypto/master-key-chain.md) | Oui, sans interruption |
| Compromission clé Node (opérationnelle) | [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md) | Oui |
| Compromission de la seed | *(hors périmètre cryptographique — voir* [`securite.incidents-compromissions`](../05-securite/incidents-compromissions.md#limite-fondamentale) *)* | Non |

## Note de conception

Dans le document source monolithique, ce tableau contenait une colonne
supplémentaire *"Limite connue"* qui **répétait en substance** des phrases
déjà présentes dans chaque section détaillée. Ici, cette information reste
sur sa page d'origine — voir par exemple la colonne "Limite connue" du
[`protocols.migration-noeud`](../04-protocols/migration-noeud.md) pour le
détail propre à ce scénario, plutôt qu'une version raccourcie et donc
potentiellement divergente ici.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
