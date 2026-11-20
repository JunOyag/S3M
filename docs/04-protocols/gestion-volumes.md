---
id: protocols.gestion-volumes
kind: narrative
title: "Gestion des Volumes du Nœud"
section: "§4.4 (ajout post-V2)"
status: draft
verified_by: []
---

# Gestion des volumes du Nœud

Fonctionnalité ajoutée le 2026-11-20. Elle complète
[`protocols.stockage-physique`](stockage-physique.md) : l'opérateur ajoute,
retire, reconfigure ou efface les volumes d'un Nœud en service, sans perte
de données ni arrêt.

## Liste des actions {: #liste-des-actions }

Les actions (ajout, retrait, chemin, capacité, effacement, volume perdu)
s'accumulent dans une **liste des actions**, puis s'appliquent d'un coup
après une fenêtre de confirmation qui les récapitule. La liste entière est
validée avant toute exécution — chemin accessible et inscriptible,
capacité au moins égale à l'occupation, place suffisante sur les autres
volumes pour un retrait, au moins un volume actif restant ; une seule
erreur et rien n'est appliqué. Le journal des volumes date chaque action.

La liste des volumes et leur état vivent dans la configuration du Nœud
(`volumes` de `node.json`, reflet local de
[`node.VolumeConfig`](../02-schemas/node/VolumeConfig.md)) : l'état ne
quitte jamais le Nœud, le schéma n'en a pas besoin.

## Marqueur de volume {: #marqueur }

À la racine de chaque volume, `s3m-volume.json` :
`{node_id, volume_id, signature}`, la signature Ed25519 par `priv_node` portant
sur `L("s3m/sig/volume-marker/v1") ‖ node_id ‖ u32(volume_id)`. À l'ajout
d'un chemin :

- **sans marqueur ni blocs** : volume neuf, marqueur écrit ;
- **marqueur valide de ce Nœud, ou blocs sans marqueur** : [import](#import) ;
- **marqueur d'un autre Nœud** : refusé ; seule option proposée, « Effacer
  et réutiliser ce disque » (voir [Effacement](#effacement)).

## Retrait : vidage annulable {: #retrait }

Un volume retiré passe à l'état **vidage** : plus aucun conteneur ni bloc
nouveau n'y est alloué, et ses blocs sont déplacés un par un vers les
autres volumes (écriture du nouvel emplacement, bascule de
`BlockLocation` et des deux bitmaps dans une même transaction, puis
libération de l'ancien slot). Chaque déplacement est atomique : on peut
**annuler** à tout moment, le volume redevient actif et les blocs déjà
déplacés restent valides où ils sont. Le retrait n'est définitif — volume
ôté de la configuration, marqueur supprimé — qu'une fois le volume vide.

## Volume perdu {: #perdu }

Disque mort ou illisible : l'opérateur le déclare perdu. Ses conteneurs
et emplacements sont oubliés ; les blocs d'Utilisateurs perdus sont
reconstruits depuis la parité par le scrubbing, déclenché aussitôt
([`securite.integrite-autoreparation`](../05-securite/integrite-autoreparation.md)) ;
les fragments hébergés pour des partenaires sont retirés de leur solde, et
chaque partenaire les reconstruit de son côté à son prochain échec de
challenge ([`securite.pos-challenges`](../05-securite/pos-challenges.md)).

## Import d'un volume contenant déjà des blocs {: #import }

Cas d'usage : disque déplacé, réinstallation du Nœud avec la même
identité. Le répertoire `blocks/` trouvé est d'abord renommé
`import-<horodatage>/` (aucune collision avec les conteneurs neufs), puis
traité en tâche de fond, conteneur par conteneur :

1. **Intégrité** : chaque slot occupé est relu ; son identifiant est le
   SHA-256 de son contenu. Un bloc abîmé produit un hash que personne ne
   reconnaît — il tombe donc au point 3.
2. **Appartenance**, selon le propriétaire du conteneur (répertoire
   `blocks/<owner_type>/<owner_id>/`) :
   - `AttachedUser` : retenu si l'Utilisateur est rattaché et si le hash
     figure dans le registre de dispersion du Nœud (blocs en attente,
     stripes de données et d'index) ;
   - `Partner` : retenu si le partenaire le confirme par
     [`OwnershipQuery`](#ownership-query) ;
   - `EmergencyDepositor` : jamais retenu (dépôts temporaires).
3. **Tri** : un bloc retenu est réécrit dans le stockage (sauf s'il y est
   déjà) ; les autres sont supprimés. Le conteneur importé est effacé une
   fois traité.

Un rapport (retenus, supprimés, par propriétaire) est affiché à la fin.
Un partenaire injoignable laisse ses blocs en attente : nouvel essai au
cycle suivant, jamais de suppression faute de réponse.

## `OwnershipQuery` {: #ownership-query }

Ajout à [`protocols.echange-blocs`](echange-blocs.md), Nœud → partenaire,
sans `credential` (identité Noise du Nœud) :

```
--8<-- "network/OwnershipQuery.table.md"
```
```
--8<-- "network/OwnershipAnswer.table.md"
```

`hashes` : SHA-256 concaténés (32 octets chacun, 1024 au plus). Le
partenaire répond, pour chacun, s'il l'a placé chez **ce** demandeur et le
tient encore pour sien (fragments de parité de ses stripes, de son index,
de son snapshot, ou en délai de grâce). `owned` : un bit par hash, dans
l'ordre (bit `i % 8` de l'octet `i / 8`). Une réponse `Failure` (partenaire
occupé) se réessaie.

## Effacement {: #effacement }

« Effacer » ne formate jamais le disque : seuls `blocks/`, `import-*/` et
le marqueur sont supprimés. Possible pour un volume vide de ce Nœud, ou
pour un disque d'un autre Nœud au moment de son ajout.

<!-- GENERATED:BACKLINKS:START (ne pas éditer, voir gen_docs.py) -->

## Référencé par

*(généré automatiquement au build)*
