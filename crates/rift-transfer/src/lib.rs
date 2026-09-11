//! Transport-independent single-file transfer mechanics.
//!
//! These routines spawn no tasks, open no network streams, and publish no files.
//! The caller owns authorization, worker capacity, durable acceptance, attempt
//! fencing, stream finish/reset, partial-file sync/cleanup, and atomic publication.

mod streaming;

pub use streaming::{
    AttemptControl, STREAM_BUFFER_SIZE, TransferIoError, hash_source, receive_payload, send_payload,
};
