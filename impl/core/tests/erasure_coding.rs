//! Invariants de `protocols.erasure-coding` (Phase 3, component core).

use p2p_storage_core::erasure::*;
use p2p_storage_core::k_block::BLOCK_SIZE;
use p2p_storage_core::CoreError;

fn data_blocks(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| (0..BLOCK_SIZE).map(|j| (i * 31 + j * 7) as u8).collect())
        .collect()
}

fn stripe(k: usize, coef: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let data = data_blocks(k);
    let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
    let parity = encode_parity(&refs, coef).unwrap();
    (data, parity)
}

fn keep(data: &[Vec<u8>], parity: &[Vec<u8>], present: &[usize]) -> Vec<Option<Vec<u8>>> {
    data.iter()
        .chain(parity)
        .enumerate()
        .map(|(i, s)| present.contains(&i).then(|| s.clone()))
        .collect()
}

/// N = k + coef×k : coef×k blocs de parité de 65 536 o (coef = 3 → N = 4k).
#[test]
fn parity_count_is_coef_times_k() {
    let (_, parity) = stripe(4, DEFAULT_COEF);
    assert_eq!(parity.len(), 12);
    assert!(parity.iter().all(|p| p.len() == BLOCK_SIZE));
}

/// N'importe quels k blocs sur N suffisent — vérifié sur tous les
/// sous-ensembles de taille k pour k = 2, coef = 3 (N = 8, 28 cas).
#[test]
fn any_k_of_n_blocks_reconstruct_the_data() {
    let (k, coef) = (2, 3);
    let (data, parity) = stripe(k, coef);
    let n = k + k * coef;
    for a in 0..n {
        for b in a + 1..n {
            let got = reconstruct_data(keep(&data, &parity, &[a, b]), k, coef).unwrap();
            assert_eq!(got, data, "sous-ensemble ({a}, {b})");
        }
    }
}

/// Perte totale du Nœud hébergeur : k blocs de parité seuls suffisent.
#[test]
fn parity_alone_reconstructs_after_total_host_loss() {
    let (k, coef) = (4, 3);
    let (data, parity) = stripe(k, coef);
    let got = reconstruct_data(keep(&data, &parity, &[5, 8, 11, 15]), k, coef).unwrap();
    assert_eq!(got, data);
}

#[test]
fn fewer_than_k_blocks_is_an_explicit_error() {
    let (k, coef) = (4, 3);
    let (data, parity) = stripe(k, coef);
    assert!(matches!(
        reconstruct_data(keep(&data, &parity, &[0, 5, 9]), k, coef),
        Err(CoreError::ErasureNotEnoughShards)
    ));
}

/// Linéarité : la parité se calcule sur des blocs chiffrés quelconques,
/// sans connaître la clé — la reconstruction rend exactement le chiffré.
#[test]
fn parity_works_on_opaque_ciphertext_blocks() {
    let (k, coef) = (3, 3);
    let opaque: Vec<Vec<u8>> = (0..k)
        .map(|i| {
            let mut b = vec![0u8; BLOCK_SIZE];
            for (j, x) in b.iter_mut().enumerate() {
                *x = ((j as u32).wrapping_mul(2_654_435_761).rotate_left(i as u32) >> 24) as u8;
            }
            b
        })
        .collect();
    let refs: Vec<&[u8]> = opaque.iter().map(|d| d.as_slice()).collect();
    let parity = encode_parity(&refs, coef).unwrap();
    let got = reconstruct_data(keep(&opaque, &parity, &[1, 4, 10]), k, coef).unwrap();
    assert_eq!(got, opaque);
}

#[test]
fn invalid_parameters_and_shard_sizes_are_rejected() {
    assert!(matches!(
        encode_parity(&[], 3),
        Err(CoreError::ErasureParameters)
    ));
    let a = vec![0u8; 10];
    let b = vec![0u8; 11];
    assert!(matches!(
        encode_parity(&[&a, &b], 3),
        Err(CoreError::ErasureShardSize)
    ));
    let big = vec![vec![0u8; 8]; 65];
    let refs: Vec<&[u8]> = big.iter().map(|d| d.as_slice()).collect();
    assert!(matches!(
        encode_parity(&refs, 3),
        Err(CoreError::ErasureParameters)
    ));
}

/// Dispersion multi-partenaires : coef×k partenaires distincts (12 pour
/// k = 4, coef = 3) ; jamais deux fragments chez le même partenaire.
#[test]
fn parity_placement_requires_coef_times_k_distinct_partners() {
    let ok: Vec<u16> = (1..=12).collect();
    assert!(check_parity_placement(&ok, 4, 3).is_ok());
    let mut dup = ok.clone();
    dup[11] = 1;
    assert!(matches!(
        check_parity_placement(&dup, 4, 3),
        Err(CoreError::ErasureDuplicatePartner)
    ));
    assert!(check_parity_placement(&ok[..11], 4, 3).is_err());
}

/// Assemblage progressif : paquets de k ; paquet incomplet complété de
/// padding après le délai d'inactivité, pas avant.
#[test]
fn stripe_assembler_groups_by_k_and_pads_after_idle_timeout() {
    let mut asm = StripeAssembler::new(4, 30).unwrap();
    for (i, t) in [(1, 0), (2, 1), (3, 2)] {
        assert_eq!(asm.push(i, t), None);
    }
    let full = asm.push(4, 3).unwrap();
    assert_eq!((full.blocks, full.padding), (vec![1, 2, 3, 4], 0));

    asm.push(5, 100);
    asm.push(6, 110);
    assert_eq!(asm.poll(140), None, "délai non écoulé");
    let partial = asm.poll(141).unwrap();
    assert_eq!((partial.blocks, partial.padding), (vec![5, 6], 2));
    assert_eq!(asm.pending(), 0);
    assert_eq!(asm.poll(10_000), None);
    assert!(padding_block().iter().all(|&b| b == 0));
    assert_eq!(padding_block().len(), BLOCK_SIZE);
}
