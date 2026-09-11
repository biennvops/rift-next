//! Transport-independent single-file transfer mechanics.
//!
//! These routines spawn no tasks, open no network streams, and publish no files.
//! The caller owns authorization, worker capacity, durable acceptance, attempt
//! fencing, stream finish/reset, partial-file sync/cleanup, and atomic publication.

mod record;
mod source;

pub use record::{
    MAX_TRANSFER_RECORD_LEN, MAX_TRANSFER_RECORD_PAYLOAD_LEN, ManifestSource, TerminalOrigin,
    TransferManifest, TransferRecord, TransferRecordError, decode_transfer_record,
    encode_transfer_record,
};
mod state;
mod streaming;

pub use source::{SourcePreparationError, prepare_source};
pub use state::{
    LogicalTransfer, OfferReplay, TransferAttempt, TransferDirection, TransferState,
    TransferTransitionError,
};

pub use streaming::{
    AttemptControl, STREAM_BUFFER_SIZE, TransferIoError, hash_source, receive_payload, send_payload,
};
