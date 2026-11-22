//! Partage (`protocols.partage`), partie commune sans I/O : autorisation de
//! lecture signée, pointeur chiffré publié dans l'annuaire, jeton, lien
//! `s3m://partage#…` et invitation `S3MS1:…`. Réf. spec :
//! docs/04-protocols/partage.md.

use flatbuffers::FlatBufferBuilder;
use s3m_core::identity_derivation::{base32_decode, base32_encode};
use s3m_core::share::{open_invite, seal_invite, share_content_key, share_dht_key, share_id};

use crate::dht::{
    build_envelope, open_blob, seal_blob, sign, verify_envelope, verify_signature, DhtError,
    EntryKind, VerifyContext,
};
use crate::exchange::Id;
use crate::fb::{dht as fbd, exchange as fb};

/// Libellé de signature d'une autorisation de partage.
pub const SIG_LABEL_SHARE_GRANT: &str = "s3m/sig/share-grant/v1";
/// Préfixe d'un lien de partage.
pub const LINK_PREFIX: &str = "s3m://partage#";
/// Préfixe d'une invitation chiffrée pour un Utilisateur S3m.
pub const INVITE_PREFIX: &str = "S3MS1:";
/// Débit servi par partage : blocs par minute.
pub const BLOCKS_PER_MINUTE: u32 = 1_000;

/// Autorisation de lecture des blocs d'un propriétaire chez son Nœud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareGrant {
    pub owner_user_id: Id,
    pub node_id: Id,
    pub share_id: Id,
    /// 0 : sans expiration.
    pub expires_at: u64,
}

fn grant_bytes(g: &ShareGrant) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let o = b.create_vector(&g.owner_user_id);
    let n = b.create_vector(&g.node_id);
    let s = b.create_vector(&g.share_id);
    let t = fb::ShareGrant::create(
        &mut b,
        &fb::ShareGrantArgs {
            owner_user_id: Some(o),
            node_id: Some(n),
            share_id: Some(s),
            expires_at: g.expires_at,
        },
    );
    b.finish_minimal(t);
    b.finished_data().to_vec()
}

/// Signe une autorisation avec `priv_user` du propriétaire : `(octets, signature)`.
pub fn sign_grant(priv_user: &[u8; 32], g: &ShareGrant) -> (Vec<u8>, Vec<u8>) {
    let bytes = grant_bytes(g);
    let sig = sign(priv_user, SIG_LABEL_SHARE_GRANT, &bytes);
    (bytes, sig.to_vec())
}

fn id32(v: Option<flatbuffers::Vector<'_, u8>>) -> Result<Id, DhtError> {
    v.ok_or(DhtError::Format("champ absent"))?
        .bytes()
        .try_into()
        .map_err(|_| DhtError::Format("taille"))
}

/// Vérifie une autorisation : signée par le propriétaire qu'elle nomme.
pub fn verify_grant(bytes: &[u8], signature: &[u8]) -> Result<ShareGrant, DhtError> {
    let t =
        flatbuffers::root::<fb::ShareGrant>(bytes).map_err(|_| DhtError::Format("ShareGrant"))?;
    let g = ShareGrant {
        owner_user_id: id32(t.owner_user_id())?,
        node_id: id32(t.node_id())?,
        share_id: id32(t.share_id())?,
        expires_at: t.expires_at(),
    };
    verify_signature(&g.owner_user_id, SIG_LABEL_SHARE_GRANT, bytes, signature)?;
    Ok(g)
}

/// Contenu chiffré d'un partage.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharePointer {
    pub share_id: Id,
    /// `true` : dossier (avec son arborescence) ; `false` : fichier.
    pub is_dir: bool,
    pub name: String,
    pub size_bytes: u64,
    pub modified_at: u64,
    pub first_block_hash: Id,
    pub element_key: Id,
    pub node_id: Id,
    pub node_addrs: Vec<String>,
    pub owner_label: String,
    /// `SignedShareGrant` : `(octets, signature)`.
    pub grant: (Vec<u8>, Vec<u8>),
    pub revoked: bool,
}

fn signed_grant_bytes(g: &(Vec<u8>, Vec<u8>)) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let gr = b.create_vector(&g.0);
    let sg = b.create_vector(&g.1);
    let t = fb::SignedShareGrant::create(
        &mut b,
        &fb::SignedShareGrantArgs {
            grant: Some(gr),
            signature: Some(sg),
        },
    );
    b.finish_minimal(t);
    b.finished_data().to_vec()
}

fn signed_grant_of(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DhtError> {
    let t = flatbuffers::root::<fb::SignedShareGrant>(bytes)
        .map_err(|_| DhtError::Format("SignedShareGrant"))?;
    Ok((
        t.grant().map(|v| v.bytes().to_vec()).unwrap_or_default(),
        t.signature()
            .map(|v| v.bytes().to_vec())
            .unwrap_or_default(),
    ))
}

fn pointer_bytes(p: &SharePointer) -> Vec<u8> {
    let mut b = FlatBufferBuilder::new();
    let sid = b.create_vector(&p.share_id);
    let name = b.create_string(&p.name);
    let first = b.create_vector(&p.first_block_hash);
    let key = b.create_vector(&p.element_key);
    let node = b.create_vector(&p.node_id);
    let addrs: Vec<_> = p.node_addrs.iter().map(|a| b.create_string(a)).collect();
    let addrs = b.create_vector(&addrs);
    let label = b.create_string(&p.owner_label);
    let grant = b.create_vector(&signed_grant_bytes(&p.grant));
    let t = fbd::SharePointer::create(
        &mut b,
        &fbd::SharePointerArgs {
            share_id: Some(sid),
            kind: u8::from(p.is_dir),
            name: Some(name),
            size_bytes: p.size_bytes,
            modified_at: p.modified_at,
            first_block_hash: Some(first),
            element_key: Some(key),
            node_id: Some(node),
            node_addrs: Some(addrs),
            owner_label: Some(label),
            grant: Some(grant),
            revoked: p.revoked,
        },
    );
    b.finish_minimal(t);
    b.finished_data().to_vec()
}

fn pointer_of(bytes: &[u8]) -> Result<SharePointer, DhtError> {
    let t = flatbuffers::root::<fbd::SharePointer>(bytes)
        .map_err(|_| DhtError::Format("SharePointer"))?;
    Ok(SharePointer {
        share_id: id32(t.share_id())?,
        is_dir: t.kind() == 1,
        name: t.name().unwrap_or_default().to_string(),
        size_bytes: t.size_bytes(),
        modified_at: t.modified_at(),
        first_block_hash: id32(t.first_block_hash())?,
        element_key: id32(t.element_key())?,
        node_id: id32(t.node_id())?,
        node_addrs: t
            .node_addrs()
            .map(|v| v.iter().map(str::to_string).collect())
            .unwrap_or_default(),
        owner_label: t.owner_label().unwrap_or_default().to_string(),
        grant: signed_grant_of(t.grant().map(|v| v.bytes()).unwrap_or_default())?,
        revoked: t.revoked(),
    })
}

/// Jeton d'un partage : secret `S` et clé publique de signature du
/// propriétaire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareToken {
    pub secret: Id,
    pub sig_pub: Id,
}

impl ShareToken {
    /// Jeton d'un nouveau partage : `S` tiré par l'appelant, clé de
    /// signature dérivée de `priv_user`.
    pub fn new(priv_user: &[u8; 32], secret: Id) -> Self {
        let seed = signing_seed(priv_user, &secret);
        let sig_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        ShareToken { secret, sig_pub }
    }

    pub fn share_id(&self) -> Id {
        share_id(&self.secret)
    }

    /// Clé de l'annuaire du pointeur.
    pub fn dht_key(&self) -> Id {
        share_dht_key(&self.sig_pub)
    }

    fn bytes(&self) -> Vec<u8> {
        [self.secret.as_slice(), self.sig_pub.as_slice()].concat()
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        (b.len() == 64).then(|| ShareToken {
            secret: b[..32].try_into().unwrap(),
            sig_pub: b[32..].try_into().unwrap(),
        })
    }

    /// Lien `s3m://partage#<jeton en base32>`.
    pub fn link(&self) -> String {
        format!("{LINK_PREFIX}{}", base32_encode(&self.bytes()))
    }

    /// Invitation chiffrée pour `recipient_pub_user` seul.
    pub fn invite(
        &self,
        recipient_pub_user: &Id,
        ephemeral: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<String, DhtError> {
        let sealed = seal_invite(recipient_pub_user, ephemeral, nonce, &self.bytes())?;
        Ok(format!("{INVITE_PREFIX}{}", base32_encode(&sealed)))
    }

    /// Lit un lien ou une invitation (avec les clés du destinataire).
    pub fn parse(text: &str, priv_user: &[u8; 32], pub_user: &Id) -> Result<Self, String> {
        let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(rest) = t.strip_prefix(LINK_PREFIX) {
            let b = base32_decode(rest).ok_or("lien de partage illisible")?;
            return Self::from_bytes(&b).ok_or_else(|| "lien de partage illisible".into());
        }
        let up = t.to_ascii_uppercase();
        if let Some(rest) = up.strip_prefix(INVITE_PREFIX) {
            let b = base32_decode(rest).ok_or("invitation illisible")?;
            let token = open_invite(priv_user, pub_user, &b)
                .map_err(|_| "cette invitation n'est pas adressée à cette identité")?;
            return Self::from_bytes(&token).ok_or_else(|| "invitation illisible".into());
        }
        Err("lien s3m://partage#… ou invitation S3MS1:… attendu".into())
    }
}

/// Graine de `sig_priv_share` d'un partage.
pub fn signing_seed(priv_user: &[u8; 32], secret: &Id) -> [u8; 32] {
    s3m_core::share::share_signing_seed(priv_user, &share_id(secret)).expect("dérivation KDF")
}

/// Enveloppe DHT du pointeur : `seq` strictement croissant, signée par la
/// clé du propriétaire pour ce partage.
pub fn share_entry_envelope(
    priv_user: &[u8; 32],
    token: &ShareToken,
    pointer: &SharePointer,
    seq: u64,
    timestamp: u64,
    nonce: &[u8; 12],
) -> Result<Vec<u8>, DhtError> {
    let k = share_content_key(&token.secret)?;
    let blob = seal_blob(
        &k,
        EntryKind::Share.blob_aad_label(),
        nonce,
        &pointer_bytes(pointer),
    )?;
    let mut b = FlatBufferBuilder::new();
    let key = b.create_vector(&token.sig_pub);
    let ptr = b.create_vector(&blob);
    let e = fbd::ShareEntry::create(
        &mut b,
        &fbd::ShareEntryArgs {
            sig_pub_share: Some(key),
            seq,
            timestamp,
            pointer: Some(ptr),
        },
    );
    fbd::finish_share_entry_buffer(&mut b, e);
    let payload = b.finished_data().to_vec();
    let seed = signing_seed(priv_user, &token.secret);
    Ok(build_envelope(
        &payload,
        &sign(&seed, EntryKind::Share.signature_label(), &payload),
    ))
}

/// Vérifie et déchiffre l'entrée d'un partage : `(seq, pointeur)`.
pub fn open_share_entry(
    envelope: &[u8],
    token: &ShareToken,
    now: u64,
) -> Result<(u64, SharePointer), DhtError> {
    let ctx = VerifyContext {
        now,
        node_lookup_key: None,
        previous_seq: None,
    };
    let no_vdf = |_: &[u8; s3m_core::vdf::TAGGED_IDENTITY_LEN],
                  _: &s3m_core::vdf::VdfProof|
     -> Result<bool, s3m_core::CoreError> { Ok(false) };
    let payload = verify_envelope(envelope, EntryKind::Share, &ctx, &no_vdf)?;
    let e = fbd::root_as_share_entry(&payload).map_err(|_| DhtError::Format("ShareEntry"))?;
    if id32(e.sig_pub_share())? != token.sig_pub {
        return Err(DhtError::BadSignature);
    }
    let k = share_content_key(&token.secret)?;
    let clear = open_blob(
        &k,
        EntryKind::Share.blob_aad_label(),
        e.pointer().map(|v| v.bytes()).unwrap_or_default(),
    )?;
    Ok((e.seq(), pointer_of(&clear)?))
}
