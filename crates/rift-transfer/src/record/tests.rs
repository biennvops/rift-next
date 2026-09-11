use rift_protocol::{TransferFailureCode, TransferFileName};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn manifest() -> Result<TransferManifest, rift_protocol::TransferMetadataError> {
    Ok(TransferManifest {
        transfer_id: TransferId::from_bytes([1; 16]),
        peer: DeviceId::from_bytes([2; 32]),
        metadata: TransferMetadata::new(TransferFileName::new("file.bin")?, 7, [3; 32])?,
        source: ManifestSource::Incoming,
    })
}

fn absolute(suffix: &str) -> String {
    if cfg!(windows) {
        format!("C:\\{suffix}")
    } else {
        format!("/{suffix}")
    }
}

fn envelope(payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFTXFER");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    bytes
}

#[test]
fn exact_format_and_all_record_variants_round_trip() -> TestResult {
    let incoming = manifest()?;
    let mut outgoing = incoming.clone();
    outgoing.source = ManifestSource::Outgoing(SourcePath::new(&absolute("private/file.bin"))?);
    let binding = incoming.record_digest()?;
    let mut records = vec![
        TransferRecord::Manifest(incoming),
        TransferRecord::Manifest(outgoing),
        TransferRecord::Accepted {
            manifest_digest: binding,
        },
    ];
    for origin in [TerminalOrigin::Local, TerminalOrigin::Peer] {
        for status in [
            TransferTerminalStatus::Completed,
            TransferTerminalStatus::Rejected,
            TransferTerminalStatus::Cancelled,
            TransferTerminalStatus::Failed(TransferFailureCode::Integrity),
            TransferTerminalStatus::Failed(TransferFailureCode::SourceChanged),
            TransferTerminalStatus::Failed(TransferFailureCode::Io),
            TransferTerminalStatus::Failed(TransferFailureCode::Resource),
            TransferTerminalStatus::Failed(TransferFailureCode::Protocol),
        ] {
            records.push(TransferRecord::Terminal {
                manifest_digest: binding,
                status,
                origin,
            });
        }
    }
    for record in records {
        let bytes = encode_transfer_record(&record)?;
        assert!(bytes.len() <= MAX_TRANSFER_RECORD_LEN);
        assert_eq!(bytes, envelope(&postcard::to_stdvec(&record)?));
        assert_eq!(decode_transfer_record(&bytes)?, record);
        assert_eq!(
            encode_transfer_record(&decode_transfer_record(&bytes)?)?,
            bytes
        );
        for truncated in 0..bytes.len() {
            assert!(decode_transfer_record(&bytes[..truncated]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            decode_transfer_record(&trailing),
            Err(TransferRecordError::Length)
        );
        for index in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            corrupt[index] ^= 1;
            assert!(
                decode_transfer_record(&corrupt).is_err(),
                "byte {index} was not protected"
            );
        }
    }
    // Fixed payload bytes pin marker/status/origin discriminants independently of Serde.
    let mut accepted = vec![1];
    accepted.extend_from_slice(&[9; 32]);
    assert_eq!(
        encode_transfer_record(&TransferRecord::Accepted {
            manifest_digest: [9; 32]
        })?,
        envelope(&accepted)
    );
    let mut terminal = vec![2];
    terminal.extend_from_slice(&[9; 32]);
    terminal.extend_from_slice(&[3, 4, 1]);
    assert_eq!(
        encode_transfer_record(&TransferRecord::Terminal {
            manifest_digest: [9; 32],
            status: TransferTerminalStatus::Failed(TransferFailureCode::Protocol),
            origin: TerminalOrigin::Peer
        })?,
        envelope(&terminal)
    );
    Ok(())
}

#[test]
fn framing_rejects_unsupported_oversized_and_corrupt_input_before_decoding() -> TestResult {
    let valid = encode_transfer_record(&TransferRecord::Manifest(manifest()?))?;
    let mut wrong_magic = valid.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        decode_transfer_record(&wrong_magic),
        Err(TransferRecordError::Magic)
    );
    for version in [0_u16, 2, u16::MAX] {
        let mut bytes = valid.clone();
        bytes[8..10].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            decode_transfer_record(&bytes),
            Err(TransferRecordError::Version)
        );
    }
    for length in [8193_u32, u32::MAX] {
        let mut prefix = valid[..HEADER_LEN].to_vec();
        prefix[10..14].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            decode_transfer_record(&prefix),
            Err(TransferRecordError::TooLarge)
        );
    }
    assert_eq!(
        decode_transfer_record(&envelope(&[])),
        Err(TransferRecordError::Length)
    );
    let mut corrupt_payload = envelope(&[255]);
    corrupt_payload[HEADER_LEN] = 254;
    assert_eq!(
        decode_transfer_record(&corrupt_payload),
        Err(TransferRecordError::Checksum)
    );
    assert_eq!(
        decode_transfer_record(&envelope(&[3])),
        Err(TransferRecordError::Decode)
    );
    let mut payload = postcard::to_stdvec(&TransferRecord::Manifest(manifest()?))?;
    payload.push(0);
    assert_eq!(
        decode_transfer_record(&envelope(&payload)),
        Err(TransferRecordError::TrailingPayload)
    );
    // An exact-bound payload is admitted by framing but still strictly decoded.
    payload.resize(MAX_TRANSFER_RECORD_PAYLOAD_LEN, 0);
    assert_eq!(
        decode_transfer_record(&envelope(&payload)),
        Err(TransferRecordError::TrailingPayload)
    );
    payload.push(0);
    assert_eq!(
        decode_transfer_record(&envelope(&payload)),
        Err(TransferRecordError::TooLarge)
    );
    Ok(())
}

#[test]
fn raw_postcard_cannot_bypass_domain_validation_or_variant_bounds() -> TestResult {
    let id = TransferId::from_bytes([1; 16]);
    let peer = DeviceId::from_bytes([2; 32]);
    // Tuples encode the same field sequence while bypassing validated constructors.
    for name in [
        "".to_owned(),
        "../private".to_owned(),
        "CON".to_owned(),
        "a".repeat(256),
    ] {
        let payload = postcard::to_stdvec(&(0_u8, id, peer, name, 7_u64, [3_u8; 32], 1_u8))?;
        assert_eq!(
            decode_transfer_record(&envelope(&payload)),
            Err(TransferRecordError::Decode)
        );
    }
    for length in [rift_protocol::MAX_TRANSFER_BYTES + 1, u64::MAX] {
        let payload = postcard::to_stdvec(&(0_u8, id, peer, "file.bin", length, [3_u8; 32], 1_u8))?;
        assert_eq!(
            decode_transfer_record(&envelope(&payload)),
            Err(TransferRecordError::Decode)
        );
    }
    for path in [
        "secret-relative".to_owned(),
        absolute("secret\0file"),
        absolute(&"s".repeat(4096)),
    ] {
        let payload =
            postcard::to_stdvec(&(0_u8, id, peer, "file.bin", 7_u64, [3_u8; 32], 0_u8, path))?;
        let result = decode_transfer_record(&envelope(&payload));
        assert_eq!(result, Err(TransferRecordError::Decode));
        assert!(!format!("{result:?}").contains("secret"));
    }
    let unsupported_source =
        postcard::to_stdvec(&(0_u8, id, peer, "file.bin", 7_u64, [3_u8; 32], 2_u8))?;
    assert_eq!(
        decode_transfer_record(&envelope(&unsupported_source)),
        Err(TransferRecordError::Decode)
    );
    for suffix in [vec![4, 0], vec![3, 5, 0], vec![0, 2]] {
        let mut payload = vec![2];
        payload.extend_from_slice(&[9; 32]);
        payload.extend_from_slice(&suffix);
        assert_eq!(
            decode_transfer_record(&envelope(&payload)),
            Err(TransferRecordError::Decode)
        );
    }
    Ok(())
}

#[test]
fn maximum_valid_manifest_is_bounded_and_debug_redacts_source() -> TestResult {
    let mut manifest = manifest()?;
    let root = absolute("");
    let path = format!("{root}{}", "s".repeat(4096 - root.len()));
    manifest.source = ManifestSource::Outgoing(SourcePath::new(&path)?);
    manifest.metadata = TransferMetadata::new(
        TransferFileName::new(&"n".repeat(255))?,
        rift_protocol::MAX_TRANSFER_BYTES,
        [255; 32],
    )?;
    let record = TransferRecord::Manifest(manifest);
    assert!(!format!("{record:?} {record:#?}").contains(&path));
    assert!(format!("{record:?}").contains("REDACTED"));
    let bytes = encode_transfer_record(&record)?;
    assert!(bytes.len() < MAX_TRANSFER_RECORD_LEN);
    assert!(
        bytes
            .windows(path.len())
            .any(|window| window == path.as_bytes())
    );
    assert_eq!(decode_transfer_record(&bytes)?, record);
    Ok(())
}

#[test]
fn markers_bind_every_immutable_manifest_field() -> TestResult {
    let original = manifest()?;
    let binding = original.record_digest()?;
    let marker = TransferRecord::Accepted {
        manifest_digest: binding,
    };
    marker.validate_marker(&original)?;
    let mut changed = original.clone();
    changed.transfer_id = TransferId::from_bytes([8; 16]);
    assert_eq!(
        marker.validate_marker(&changed),
        Err(TransferRecordError::ManifestMismatch)
    );
    changed = original.clone();
    changed.peer = DeviceId::from_bytes([8; 32]);
    assert_eq!(
        marker.validate_marker(&changed),
        Err(TransferRecordError::ManifestMismatch)
    );
    for metadata in [
        TransferMetadata::new(TransferFileName::new("other.bin")?, 7, [3; 32])?,
        TransferMetadata::new(TransferFileName::new("file.bin")?, 8, [3; 32])?,
        TransferMetadata::new(TransferFileName::new("file.bin")?, 7, [4; 32])?,
    ] {
        changed = original.clone();
        changed.metadata = metadata;
        assert_eq!(
            marker.validate_marker(&changed),
            Err(TransferRecordError::ManifestMismatch)
        );
    }
    changed = original.clone();
    changed.source = ManifestSource::Outgoing(SourcePath::new(&absolute("private/a"))?);
    assert_eq!(
        marker.validate_marker(&changed),
        Err(TransferRecordError::ManifestMismatch)
    );
    let outgoing_binding = changed.record_digest()?;
    changed.source = ManifestSource::Outgoing(SourcePath::new(&absolute("private/b"))?);
    assert_ne!(changed.record_digest()?, outgoing_binding);
    assert_eq!(
        TransferRecord::Manifest(original.clone()).validate_marker(&original),
        Err(TransferRecordError::NotMarker)
    );
    Ok(())
}

#[test]
fn marker_roles_are_receiver_authoritative_but_do_not_establish_durability() -> TestResult {
    for incoming in [true, false] {
        let mut manifest = manifest()?;
        if !incoming {
            manifest.source =
                ManifestSource::Outgoing(SourcePath::new(&absolute("private/file.bin"))?);
        }
        let binding = manifest.record_digest()?;
        let accepted = TransferRecord::Accepted {
            manifest_digest: binding,
        };
        assert_eq!(
            accepted.validate_marker(&manifest),
            if incoming {
                Ok(())
            } else {
                Err(TransferRecordError::InvalidRole)
            }
        );
        for origin in [TerminalOrigin::Local, TerminalOrigin::Peer] {
            for status in [
                TransferTerminalStatus::Completed,
                TransferTerminalStatus::Rejected,
                TransferTerminalStatus::Cancelled,
                TransferTerminalStatus::Failed(TransferFailureCode::Io),
            ] {
                let terminal = TransferRecord::Terminal {
                    manifest_digest: binding,
                    status,
                    origin,
                };
                let receiver_only = matches!(
                    status,
                    TransferTerminalStatus::Completed | TransferTerminalStatus::Rejected
                );
                let allowed = !receiver_only || incoming == (origin == TerminalOrigin::Local);
                assert_eq!(
                    terminal.validate_marker(&manifest),
                    if allowed {
                        Ok(())
                    } else {
                        Err(TransferRecordError::InvalidRole)
                    }
                );
                let wrong = TransferRecord::Terminal {
                    manifest_digest: [0; 32],
                    status,
                    origin,
                };
                assert_eq!(
                    wrong.validate_marker(&manifest),
                    Err(TransferRecordError::ManifestMismatch)
                );
            }
        }
    }
    Ok(())
}
