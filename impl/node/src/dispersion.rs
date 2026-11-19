//! Protocole transactionnel de dispersion — id
//! `protocols.dispersion-transactionnelle`, component `node` (Phase 3).
//! Réf. spec : docs/04-protocols/dispersion-transactionnelle.md.
//!
//! Machine à états pure (le transport vers les partenaires relève du
//! protocole d'échange de blocs, `impl/SPEC_GAPS.md`) :
//! 1. dispersion **ascendante** : un niveau d'index n'est dispersé que
//!    lorsque toutes les stripes du niveau inférieur sont confirmées ;
//! 2. **seuil k+2** confirmations de partenaires distincts par stripe ;
//! 3. commit = publication DHT, seulement une fois la racine confirmée ;
//! 4. purge différée des blocs orphelins après un délai de grâce ;
//! 5. journal d'événements rejouable de façon **idempotente**.

use std::collections::{BTreeSet, HashMap, HashSet};

/// Identifiant de stripe (hash de contenu).
pub type StripeId = [u8; 32];

/// Événement journalisé (reprise après crash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Dispersed(StripeId),
    Confirmed(StripeId, u16),
    Committed { at: u64 },
}

/// Erreurs de la transaction.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DispersionError {
    #[error("stripe inconnue de la transaction")]
    UnknownStripe,
    #[error("dispersion hors ordre : le niveau inférieur n'est pas confirmé")]
    OutOfOrder,
    #[error("racine non confirmée : commit impossible")]
    RootNotConfirmed,
    #[error("transaction vide")]
    Empty,
}

/// Transaction de dispersion d'une nouvelle version du DispersalManifest.
#[derive(Debug, Clone)]
pub struct DispersalTransaction {
    k: usize,
    /// Stripes par niveau, feuilles d'abord ; le dernier niveau est la racine.
    levels: Vec<Vec<StripeId>>,
    level_of: HashMap<StripeId, usize>,
    dispersed: HashSet<StripeId>,
    confirmations: HashMap<StripeId, BTreeSet<u16>>,
    committed_at: Option<u64>,
    journal: Vec<Event>,
}

impl DispersalTransaction {
    /// `levels` : stripes modifiées par niveau (feuilles → racine, racine
    /// unique en dernier).
    pub fn new(k: usize, levels: Vec<Vec<StripeId>>) -> Result<Self, DispersionError> {
        if levels.is_empty() || levels.last().map(|l| l.len()) != Some(1) {
            return Err(DispersionError::Empty);
        }
        let level_of = levels
            .iter()
            .enumerate()
            .flat_map(|(l, ids)| ids.iter().map(move |id| (*id, l)))
            .collect();
        Ok(Self {
            k,
            levels,
            level_of,
            dispersed: HashSet::new(),
            confirmations: HashMap::new(),
            committed_at: None,
            journal: Vec::new(),
        })
    }

    /// Seuil de confirmation : k + 2 partenaires distincts.
    pub fn threshold(&self) -> usize {
        self.k + 2
    }

    fn confirmed(&self, id: &StripeId) -> bool {
        self.confirmations.get(id).map_or(0, |c| c.len()) >= self.threshold()
    }

    fn level_confirmed(&self, level: usize) -> bool {
        self.levels[level].iter().all(|id| self.confirmed(id))
    }

    /// Stripes dispersables maintenant : celles du plus bas niveau non
    /// entièrement dispersé, pourvu que tous les niveaux inférieurs soient
    /// confirmés.
    pub fn next_to_disperse(&self) -> Vec<StripeId> {
        for (l, ids) in self.levels.iter().enumerate() {
            if l > 0 && !self.level_confirmed(l - 1) {
                return Vec::new();
            }
            let todo: Vec<_> = ids
                .iter()
                .filter(|id| !self.dispersed.contains(*id))
                .copied()
                .collect();
            if !todo.is_empty() {
                return todo;
            }
        }
        Vec::new()
    }

    /// Enregistre l'envoi de la parité d'une stripe.
    pub fn mark_dispersed(&mut self, id: StripeId) -> Result<(), DispersionError> {
        let level = *self
            .level_of
            .get(&id)
            .ok_or(DispersionError::UnknownStripe)?;
        if level > 0 && !self.level_confirmed(level - 1) {
            return Err(DispersionError::OutOfOrder);
        }
        if self.dispersed.insert(id) {
            self.journal.push(Event::Dispersed(id));
        }
        Ok(())
    }

    /// Enregistre la confirmation d'un partenaire (un partenaire ne compte
    /// qu'une fois par stripe).
    pub fn confirm(&mut self, id: StripeId, partner: u16) -> Result<(), DispersionError> {
        if !self.level_of.contains_key(&id) {
            return Err(DispersionError::UnknownStripe);
        }
        if !self.dispersed.contains(&id) {
            return Err(DispersionError::OutOfOrder);
        }
        if self.confirmations.entry(id).or_default().insert(partner) {
            self.journal.push(Event::Confirmed(id, partner));
        }
        Ok(())
    }

    /// Racine confirmée : la publication DHT (fire-and-forget) peut avoir lieu.
    pub fn root(&self) -> StripeId {
        self.levels.last().unwrap()[0]
    }

    /// Commit : n'est accepté qu'une fois la racine confirmée. Rend l'id de
    /// la racine à publier (`dispersal_root_hash`).
    pub fn commit(&mut self, now: u64) -> Result<StripeId, DispersionError> {
        if !self.confirmed(&self.root()) {
            return Err(DispersionError::RootNotConfirmed);
        }
        if self.committed_at.is_none() {
            self.committed_at = Some(now);
            self.journal.push(Event::Committed { at: now });
        }
        Ok(self.root())
    }

    pub fn is_committed(&self) -> bool {
        self.committed_at.is_some()
    }

    /// Journal des événements (à persister).
    pub fn journal(&self) -> &[Event] {
        &self.journal
    }

    /// Reprise après crash : rejoue un journal ; rejouer deux fois le même
    /// événement est sans effet (idempotence).
    pub fn replay(&mut self, events: &[Event]) -> Result<(), DispersionError> {
        for e in events {
            match e {
                Event::Dispersed(id) => self.mark_dispersed(*id)?,
                Event::Confirmed(id, p) => self.confirm(*id, *p)?,
                Event::Committed { at } => {
                    self.commit(*at)?;
                }
            }
        }
        Ok(())
    }

    /// Purge différée : après commit et délai de grâce, rend les blocs de
    /// l'ancienne version absents de la nouvelle (à tombstoner).
    pub fn purge_due(
        &self,
        old_blocks: &HashSet<[u8; 32]>,
        new_blocks: &HashSet<[u8; 32]>,
        now: u64,
        grace_s: u64,
    ) -> Vec<[u8; 32]> {
        match self.committed_at {
            Some(at) if now >= at.saturating_add(grace_s) => {
                let mut v: Vec<_> = old_blocks.difference(new_blocks).copied().collect();
                v.sort();
                v
            }
            _ => Vec::new(),
        }
    }
}
