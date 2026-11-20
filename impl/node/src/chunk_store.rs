//! Stockage des blocs vu du service d'échange (`protocols.echange-blocs`) :
//! blocs de données des Utilisateurs rattachés et fragments hébergés pour les
//! partenaires. Deux implémentations : [`MemoryStore`] (tests) et
//! [`PhysicalStore`] (disque, `protocols.stockage-physique`).

use std::collections::HashMap;

use crate::{Owner, OwnerType, PhysicalStore, StorageError, BLOCK_SIZE};

pub type Id = [u8; 32];

/// Espace de rangement d'un bloc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Space {
    /// Bloc de données d'un Utilisateur rattaché (propriétaire : `pub_user`).
    UserBlock,
    /// Fragment de parité d'un partenaire (propriétaire : `pub_node`).
    Fragment,
}

impl Space {
    fn owner_type(self) -> OwnerType {
        match self {
            Space::UserBlock => OwnerType::AttachedUser,
            Space::Fragment => OwnerType::Partner,
        }
    }
}

/// Erreurs de stockage.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("taille de bloc invalide")]
    BadSize,
    #[error("hash détenu par un autre propriétaire")]
    Conflict,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Stockage adressé par hash, avec propriétaire.
pub trait ChunkStore: Send {
    /// `(propriétaire, contenu)` d'un bloc de l'espace `space`.
    fn get(&self, space: Space, hash: &Id) -> Option<(Id, Vec<u8>)>;
    fn contains(&self, hash: &Id) -> bool;
    fn put(&mut self, space: Space, owner: &Id, hash: &Id, data: &[u8]) -> Result<(), StoreError>;
    /// Supprime le bloc s'il appartient à `owner` ; rend vrai s'il existait.
    fn remove(&mut self, space: Space, owner: &Id, hash: &Id) -> bool;
    /// Supprime tous les blocs de `owner` dans `space`.
    fn remove_owner(&mut self, space: Space, owner: &Id);
    /// Propriétaires présents dans `space`.
    fn owners(&self, space: Space) -> Vec<Id>;
    /// Hashes des blocs de `owner` dans `space`.
    fn hashes(&self, space: Space, owner: &Id) -> Vec<Id>;
    /// Stockage physique sous-jacent (gestion des volumes), s'il y en a un.
    fn physical(&mut self) -> Option<&mut PhysicalStore> {
        None
    }
    /// Réécrit le contenu d'un bloc (auto-réparation de la copie locale).
    fn replace(
        &mut self,
        space: Space,
        owner: &Id,
        hash: &Id,
        data: &[u8],
    ) -> Result<(), StoreError>;
}

/// Stockage en mémoire (tests, tailles libres).
#[derive(Debug, Default)]
pub struct MemoryStore(HashMap<Id, (Space, Id, Vec<u8>)>);

impl ChunkStore for MemoryStore {
    fn get(&self, space: Space, hash: &Id) -> Option<(Id, Vec<u8>)> {
        self.0
            .get(hash)
            .filter(|(s, _, _)| *s == space)
            .map(|(_, o, d)| (*o, d.clone()))
    }

    fn contains(&self, hash: &Id) -> bool {
        self.0.contains_key(hash)
    }

    fn put(&mut self, space: Space, owner: &Id, hash: &Id, data: &[u8]) -> Result<(), StoreError> {
        match self.0.get(hash) {
            Some((s, o, _)) if *s != space || o != owner => Err(StoreError::Conflict),
            Some(_) => Ok(()),
            None => {
                self.0.insert(*hash, (space, *owner, data.to_vec()));
                Ok(())
            }
        }
    }

    fn remove(&mut self, space: Space, owner: &Id, hash: &Id) -> bool {
        if self.get(space, hash).is_some_and(|(o, _)| o == *owner) {
            self.0.remove(hash);
            return true;
        }
        false
    }

    fn remove_owner(&mut self, space: Space, owner: &Id) {
        self.0.retain(|_, (s, o, _)| !(*s == space && o == owner));
    }

    fn owners(&self, space: Space) -> Vec<Id> {
        let mut v: Vec<Id> = self
            .0
            .values()
            .filter(|(s, _, _)| *s == space)
            .map(|(_, o, _)| *o)
            .collect();
        v.sort();
        v.dedup();
        v
    }

    fn replace(
        &mut self,
        space: Space,
        owner: &Id,
        hash: &Id,
        data: &[u8],
    ) -> Result<(), StoreError> {
        self.0.insert(*hash, (space, *owner, data.to_vec()));
        Ok(())
    }

    fn hashes(&self, space: Space, owner: &Id) -> Vec<Id> {
        self.0
            .iter()
            .filter(|(_, (s, o, _))| *s == space && o == owner)
            .map(|(h, _)| *h)
            .collect()
    }
}

fn owner(space: Space, id: &Id) -> Owner {
    Owner {
        owner_type: space.owner_type(),
        owner_id: id.to_vec(),
    }
}

impl ChunkStore for PhysicalStore {
    fn physical(&mut self) -> Option<&mut PhysicalStore> {
        Some(self)
    }
    fn get(&self, space: Space, hash: &Id) -> Option<(Id, Vec<u8>)> {
        let loc = self.location(hash).ok()??;
        let c = self.container(loc.container_id).ok()?;
        if c.owner_type != space.owner_type() {
            return None;
        }
        let o: Id = c.owner_id.as_slice().try_into().ok()?;
        Some((o, self.read_block(hash).ok()??))
    }

    fn contains(&self, hash: &Id) -> bool {
        self.location(hash).ok().flatten().is_some()
    }

    fn put(
        &mut self,
        space: Space,
        owner_id: &Id,
        hash: &Id,
        data: &[u8],
    ) -> Result<(), StoreError> {
        if data.len() != BLOCK_SIZE {
            return Err(StoreError::BadSize);
        }
        if self.contains(hash) {
            return match self.get(space, hash) {
                Some((o, _)) if o == *owner_id => Ok(()),
                _ => Err(StoreError::Conflict),
            };
        }
        self.write_block(&owner(space, owner_id), hash, data)?;
        Ok(())
    }

    fn remove(&mut self, space: Space, owner_id: &Id, hash: &Id) -> bool {
        if self.get(space, hash).is_some_and(|(o, _)| o == *owner_id) {
            return self.remove_block(hash).unwrap_or(false);
        }
        false
    }

    fn remove_owner(&mut self, space: Space, owner_id: &Id) {
        let _ = PhysicalStore::remove_owner(self, &owner(space, owner_id));
    }

    fn owners(&self, space: Space) -> Vec<Id> {
        self.owner_ids(space.owner_type())
            .into_iter()
            .filter_map(|o| o.as_slice().try_into().ok())
            .collect()
    }

    fn replace(
        &mut self,
        space: Space,
        owner_id: &Id,
        hash: &Id,
        data: &[u8],
    ) -> Result<(), StoreError> {
        if data.len() != BLOCK_SIZE {
            return Err(StoreError::BadSize);
        }
        let o = owner(space, owner_id);
        if self.contains(hash) {
            self.replace_block(&o, hash, hash, data)?;
        } else {
            self.write_block(&o, hash, data)?;
        }
        Ok(())
    }

    fn hashes(&self, space: Space, owner_id: &Id) -> Vec<Id> {
        self.block_hashes(&owner(space, owner_id))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|h| h.as_slice().try_into().ok())
            .collect()
    }
}
