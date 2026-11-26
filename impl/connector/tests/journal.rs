//! Conservation du journal (`deploiement.packaging#journal`).

use s3m_connector::daemon::{log_days, purge_log, LOG_DAYS};

#[test]
fn old_log_lines_are_purged_and_the_retention_is_configurable() {
    let dir = std::env::temp_dir().join(format!("p2p-journal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let now = 2_000_000_000u64;
    let log = dir.join("s3m.log");
    let old = now - 100 * 86_400;
    let recent = now - 10 * 86_400;
    std::fs::write(&log, format!("{old} ancienne ligne\nsans date\n{recent} ligne récente\n")).unwrap();
    assert_eq!(log_days(&dir), LOG_DAYS);
    assert_eq!(purge_log(&log, 90, now).unwrap(), 1);
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(!text.contains("ancienne") && text.contains("sans date") && text.contains("récente"));
    std::fs::write(dir.join("conservation-jours"), "7").unwrap();
    assert_eq!(log_days(&dir), 7);
    assert_eq!(purge_log(&log, log_days(&dir), now).unwrap(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
