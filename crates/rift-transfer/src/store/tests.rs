use std::{fs, time::Duration};

use rift_protocol::{TransferFileName, TransferMetadata};
use tokio::sync::watch;

use super::*;
use crate::encode_transfer_record;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn control() -> Result<(watch::Sender<bool>, AttemptControl), TransferIoError> {
    let (owner, receiver) = watch::channel(false);
    Ok((
        owner,
        AttemptControl::new(receiver, Duration::from_secs(5))?,
    ))
}

fn permissions(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

fn manifest(number: u64, peer: u64) -> Result<TransferManifest, TransferRecordError> {
    let mut id = [0; 16];
    id[8..].copy_from_slice(&number.to_be_bytes());
    let mut peer_id = [0; 32];
    peer_id[24..].copy_from_slice(&peer.to_be_bytes());
    let metadata = TransferMetadata::new(
        TransferFileName::new("file.bin").map_err(|_| TransferRecordError::Decode)?,
        7,
        [3; 32],
    )
    .map_err(|_| TransferRecordError::Decode)?;
    Ok(TransferManifest {
        transfer_id: TransferId::from_bytes(id),
        peer: DeviceId::from_bytes(peer_id),
        metadata,
        source: ManifestSource::Incoming,
    })
}

fn write_record(directory: &Path, name: &str, record: &TransferRecord) -> TestResult {
    let path = directory.join(name);
    fs::write(&path, encode_transfer_record(record)?)?;
    permissions(&path, 0o600)?;
    Ok(())
}

fn state_record(
    root: &Path,
    manifest: &TransferManifest,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let directory = root.join(manifest.transfer_id.to_string());
    fs::create_dir(&directory)?;
    permissions(&directory, 0o700)?;
    write_record(
        &directory,
        "manifest",
        &TransferRecord::Manifest(manifest.clone()),
    )?;
    Ok(directory)
}

fn root() -> Result<tempfile::TempDir, io::Error> {
    let root = tempfile::tempdir()?;
    permissions(root.path(), 0o700)?;
    Ok(root)
}

#[tokio::test]
async fn scans_pending_accepted_and_terminal_records_in_id_order_without_mutating_files()
-> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    assert!(
        scan_transfer_state(root.path(), &mut control)
            .await?
            .is_empty()
    );
    for number in [3, 1, 2] {
        let manifest = manifest(number, 1)?;
        let directory = state_record(root.path(), &manifest)?;
        let binding = manifest.record_digest()?;
        if number >= 2 {
            write_record(
                &directory,
                "accepted",
                &TransferRecord::Accepted {
                    manifest_digest: binding,
                },
            )?;
        }
        if number == 3 {
            write_record(
                &directory,
                "terminal",
                &TransferRecord::Terminal {
                    manifest_digest: binding,
                    status: TransferTerminalStatus::Completed,
                    origin: TerminalOrigin::Local,
                },
            )?;
        }
    }
    let snapshot = scan_transfer_state(root.path(), &mut control).await?;
    assert_eq!(snapshot.len(), 3);
    for ((id, record), number) in snapshot.iter().zip(1..=3) {
        assert_eq!(*id, manifest(number, 1)?.transfer_id);
        assert_eq!(record.manifest(), &manifest(number, 1)?);
        assert_eq!(record.accepted(), number >= 2);
        assert_eq!(
            record.terminal(),
            if number == 3 {
                Some((TransferTerminalStatus::Completed, TerminalOrigin::Local))
            } else {
                None
            }
        );
        let directory = root.path().join(id.to_string());
        assert_eq!(
            fs::read(directory.join("manifest"))?,
            encode_transfer_record(&TransferRecord::Manifest(manifest(number, 1)?))?
        );
        assert_eq!(fs::read_dir(directory)?.count(), number as usize);
    }
    assert_eq!(
        scan_transfer_state(root.path(), &mut control).await?.len(),
        3
    );
    Ok(())
}

#[tokio::test]
async fn missing_unknown_noncanonical_and_incomplete_entries_fail_closed() -> TestResult {
    let (_owner, mut control) = control()?;
    let root = root()?;
    assert!(matches!(
        scan_transfer_state(&root.path().join("missing"), &mut control).await,
        Err(TransferStoreError::Io(TransferIoError::LocalIo(
            io::ErrorKind::NotFound
        )))
    ));
    for name in [
        "unknown",
        "ABCDEF0123456789ABCDEF0123456789",
        ".manifest.tmp",
    ] {
        let path = root.path().join(name);
        fs::create_dir(&path)?;
        assert!(matches!(
            scan_transfer_state(root.path(), &mut control).await,
            Err(TransferStoreError::InvalidEntry)
        ));
        fs::remove_dir(path)?;
    }
    let manifest = manifest(1, 1)?;
    let directory = root.path().join(manifest.transfer_id.to_string());
    fs::create_dir(&directory)?;
    permissions(&directory, 0o700)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::MissingManifest)
    ));
    write_record(
        &directory,
        "accepted",
        &TransferRecord::Accepted {
            manifest_digest: manifest.record_digest()?,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::MissingManifest)
    ));
    write_record(
        &directory,
        "manifest",
        &TransferRecord::Manifest(manifest.clone()),
    )?;
    fs::write(directory.join(".manifest.tmp"), b"interrupted")?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::InvalidEntry)
    ));
    assert_eq!(fs::read(directory.join(".manifest.tmp"))?, b"interrupted");
    Ok(())
}

#[tokio::test]
async fn manifest_id_record_kind_and_marker_binding_are_checked() -> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    let original = manifest(1, 1)?;
    let directory = state_record(root.path(), &original)?;
    write_record(
        &directory,
        "manifest",
        &TransferRecord::Manifest(manifest(2, 1)?),
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::ManifestIdMismatch)
    ));
    write_record(
        &directory,
        "manifest",
        &TransferRecord::Accepted {
            manifest_digest: original.record_digest()?,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::WrongRecordKind)
    ));
    write_record(
        &directory,
        "manifest",
        &TransferRecord::Manifest(original.clone()),
    )?;
    write_record(
        &directory,
        "accepted",
        &TransferRecord::Accepted {
            manifest_digest: manifest(1, 2)?.record_digest()?,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Record(
            TransferRecordError::ManifestMismatch
        ))
    ));
    write_record(&directory, "accepted", &TransferRecord::Manifest(original))?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::WrongRecordKind)
    ));
    Ok(())
}

#[tokio::test]
async fn corruption_and_oversized_files_do_not_yield_a_partial_snapshot() -> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    state_record(root.path(), &manifest(1, 1)?)?;
    let manifest = manifest(2, 1)?;
    let directory = state_record(root.path(), &manifest)?;
    let path = directory.join("manifest");
    let valid = encode_transfer_record(&TransferRecord::Manifest(manifest))?;
    let mut corrupt = valid.clone();
    corrupt[14] ^= 1;
    fs::write(&path, &corrupt)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Record(TransferRecordError::Checksum))
    ));
    fs::write(&path, &valid[..valid.len() - 1])?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Record(TransferRecordError::Length))
    ));
    fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(MAX_TRANSFER_RECORD_LEN as u64 + 1)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::RecordTooLarge)
    ));
    assert_eq!(
        fs::metadata(&path)?.len(),
        MAX_TRANSFER_RECORD_LEN as u64 + 1
    );
    Ok(())
}

#[tokio::test]
async fn acceptance_and_terminal_semantics_are_checked_before_snapshot_publication() -> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    let mut manifest = manifest(1, 1)?;
    let directory = state_record(root.path(), &manifest)?;
    let binding = manifest.record_digest()?;
    write_record(
        &directory,
        "terminal",
        &TransferRecord::Terminal {
            manifest_digest: binding,
            status: TransferTerminalStatus::Completed,
            origin: TerminalOrigin::Local,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::InconsistentMarkers)
    ));
    write_record(
        &directory,
        "accepted",
        &TransferRecord::Accepted {
            manifest_digest: binding,
        },
    )?;
    assert_eq!(
        scan_transfer_state(root.path(), &mut control).await?.len(),
        1
    );
    write_record(
        &directory,
        "terminal",
        &TransferRecord::Terminal {
            manifest_digest: binding,
            status: TransferTerminalStatus::Rejected,
            origin: TerminalOrigin::Local,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::InconsistentMarkers)
    ));
    fs::remove_file(directory.join("accepted"))?;
    assert_eq!(
        scan_transfer_state(root.path(), &mut control).await?.len(),
        1
    );
    write_record(
        &directory,
        "terminal",
        &TransferRecord::Terminal {
            manifest_digest: binding,
            status: TransferTerminalStatus::Completed,
            origin: TerminalOrigin::Peer,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Record(TransferRecordError::InvalidRole))
    ));
    manifest.source = ManifestSource::Outgoing(rift_core::SourcePath::from_path(
        &directory.join("private.bin"),
    )?);
    let binding = manifest.record_digest()?;
    write_record(&directory, "manifest", &TransferRecord::Manifest(manifest))?;
    write_record(
        &directory,
        "terminal",
        &TransferRecord::Terminal {
            manifest_digest: binding,
            status: TransferTerminalStatus::Completed,
            origin: TerminalOrigin::Peer,
        },
    )?;
    let records = scan_transfer_state(root.path(), &mut control).await?;
    assert!(!format!("{records:?}").contains("private.bin"));
    write_record(
        &directory,
        "accepted",
        &TransferRecord::Accepted {
            manifest_digest: binding,
        },
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Record(TransferRecordError::InvalidRole))
    ));
    Ok(())
}

#[tokio::test]
async fn hard_per_peer_bound_is_enforced_including_terminal_receipts() -> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    for number in 0..MAX_DURABLE_TRANSFERS_PER_PEER {
        let manifest = manifest(number as u64, 1)?;
        let directory = state_record(root.path(), &manifest)?;
        write_record(
            &directory,
            "terminal",
            &TransferRecord::Terminal {
                manifest_digest: manifest.record_digest()?,
                status: TransferTerminalStatus::Cancelled,
                origin: TerminalOrigin::Peer,
            },
        )?;
    }
    assert_eq!(
        scan_transfer_state(root.path(), &mut control).await?.len(),
        MAX_DURABLE_TRANSFERS_PER_PEER
    );
    state_record(
        root.path(),
        &manifest(MAX_DURABLE_TRANSFERS_PER_PEER as u64, 1)?,
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::PeerRecordLimit)
    ));
    Ok(())
}

#[tokio::test]
async fn hard_total_record_bound_is_enforced_without_unbounded_collection() -> TestResult {
    let root = root()?;
    let (_owner, mut control) = control()?;
    for number in 0..MAX_DURABLE_TRANSFERS {
        state_record(
            root.path(),
            &manifest(
                number as u64,
                (number / MAX_DURABLE_TRANSFERS_PER_PEER) as u64,
            )?,
        )?;
    }
    assert_eq!(
        scan_transfer_state(root.path(), &mut control).await?.len(),
        MAX_DURABLE_TRANSFERS
    );
    state_record(
        root.path(),
        &manifest(MAX_DURABLE_TRANSFERS as u64, MAX_DURABLE_TRANSFERS as u64)?,
    )?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::RecordLimit)
    ));
    Ok(())
}

#[tokio::test]
async fn cancelled_or_ownerless_scan_does_not_open_even_a_missing_directory() -> TestResult {
    let root = root()?;
    let (owner, mut control) = control()?;
    owner.send(true)?;
    assert!(matches!(
        scan_transfer_state(&root.path().join("missing"), &mut control).await,
        Err(TransferStoreError::Io(TransferIoError::Cancelled))
    ));
    owner.send(false)?;
    drop(owner);
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::Io(TransferIoError::Cancelled))
    ));
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_hardlinks_nonregular_files_and_unsafe_modes_fail_before_reads() -> TestResult {
    use std::os::unix::fs::symlink;
    let root = root()?;
    let (_owner, mut control) = control()?;
    let manifest = manifest(1, 1)?;
    let directory = state_record(root.path(), &manifest)?;
    let path = directory.join("manifest");
    for mode in [0o644, 0o660, 0o700, 0o4600] {
        permissions(&path, mode)?;
        assert!(matches!(
            scan_transfer_state(root.path(), &mut control).await,
            Err(TransferStoreError::InsecurePermissions)
        ));
    }
    permissions(&path, 0o600)?;
    for target in [root.path(), directory.as_path()] {
        permissions(target, 0o755)?;
        assert!(matches!(
            scan_transfer_state(root.path(), &mut control).await,
            Err(TransferStoreError::InsecurePermissions)
        ));
        permissions(target, 0o700)?;
    }
    let outside = tempfile::tempdir()?;
    let alias = outside.path().join("alias");
    fs::hard_link(&path, &alias)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::UnsafeEntry)
    ));
    fs::remove_file(&alias)?;
    fs::rename(&path, &alias)?;
    for target in [
        alias.as_path(),
        Path::new("/dev/null"),
        Path::new("/does-not-exist"),
    ] {
        symlink(target, &path)?;
        assert!(matches!(
            scan_transfer_state(root.path(), &mut control).await,
            Err(TransferStoreError::UnsafeEntry)
        ));
        fs::remove_file(&path)?;
    }
    fs::create_dir(&path)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::UnsafeEntry)
    ));
    fs::remove_dir(&path)?;
    fs::rename(&alias, &path)?;
    let record_alias = outside.path().join("record");
    fs::rename(&directory, &record_alias)?;
    symlink(&record_alias, &directory)?;
    assert!(matches!(
        scan_transfer_state(root.path(), &mut control).await,
        Err(TransferStoreError::UnsafeEntry)
    ));
    let root_alias = outside.path().join("state");
    symlink(root.path(), &root_alias)?;
    assert!(matches!(
        scan_transfer_state(&root_alias, &mut control).await,
        Err(TransferStoreError::UnsafeEntry)
    ));
    Ok(())
}
