---
id: protocols.integrite-lecture
kind: narrative
title: "Vérification d'Intégrité & Gestion des Incohérences"
section: "§3.12.1"
status: draft
verified_by: []
---

# Vérification d'Intégrité & Gestion des Incohérences

À chaque bloc reçu du Nœud ([`protocols.acces-applicatif`](acces-applicatif.md)),
le Connecteur recalcule le hash du contenu (ciphertext) reçu et le compare
au `block_hash` attendu (porté par la
[`fs.DirectoryEntry`](../02-schemas/fs/DirectoryEntry.md), ou par
`first_block_hash`/`next_hash` du bloc précédent).

## En cas d'incohérence

1. **Nouvelle tentative** auprès du même Nœud (transitoire possible :
   erreur réseau, lecture disque).
2. Si l'incohérence persiste, reconstruction via le **chemin de secours**
   (k fragments de parité chez les partenaires,
   [`protocols.erasure-coding`](erasure-coding.md)) pour ce bloc précis :
   - Hash **correct** obtenu → la copie locale du Nœud est corrompue. Le
     Connecteur sert la version reconstruite, **signale l'incident au
     Nœud** (réparation, voir
     [`securite.integrite-autoreparation`](../05-securite/integrite-autoreparation.md)),
     et journalise l'événement.
   - Hash **encore incohérent** (ou échec faute de k fragments) → bloc
     **irrécupérable**. Marqué corrompu dans le `UserManifest` local,
     erreur critique explicite affichée à l'utilisateur (nommant le
     fichier/répertoire affecté).

Cette vérification protège contre un Nœud compromis, buggé, ou victime de
corruption silencieuse — le PoS
([`securite.pos-challenges`](../05-securite/pos-challenges.md)) ne couvre
que les partenaires, jamais la copie locale du Nœud.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*

<!-- GENERATED:BACKLINKS:END -->
