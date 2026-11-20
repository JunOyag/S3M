//! Capacités de bloc mesurées — ids `fs.FileBlock`, `fs.DirectoryBlock`.

use s3m_protocol::layout::{
    fits_in_block, serialized_file_block_len, serialized_reference_directory_block_len,
    DIRECTORY_BLOCK_REFERENCE_ENTRIES, FILE_BLOCK_DATA_BYTES,
};

/// `FILE_BLOCK_DATA_BYTES` est exactement la plus grande taille de `data`
/// dont le `FileBlock` sérialisé (avec `next_hash`) tient dans 65 506 o.
#[test]
fn file_block_data_bytes_is_measured() {
    let max = (0..=65_506usize)
        .rev()
        .find(|&n| fits_in_block(serialized_file_block_len(n, true)))
        .expect("au moins une taille tient");
    assert_eq!(FILE_BLOCK_DATA_BYTES, max, "valeur mesurée : {max}");
    assert!(!fits_in_block(serialized_file_block_len(max + 1, true)));
    // Dernier bloc (sans next_hash) : la même capacité tient a fortiori.
    assert!(fits_in_block(serialized_file_block_len(max, false)));
}

/// Capacité du `DirectoryBlock` de référence (spec : « ≤ 300 entrées, à
/// re-mesurer par un test »).
#[test]
fn directory_block_reference_capacity_is_measured() {
    let max = (1..=400usize)
        .take_while(|&n| fits_in_block(serialized_reference_directory_block_len(n)))
        .last()
        .expect("au moins une entrée tient");
    assert_eq!(
        DIRECTORY_BLOCK_REFERENCE_ENTRIES, max,
        "valeur mesurée : {max}"
    );
}
