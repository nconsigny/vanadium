/// This module contains the constants for a communication protocol that builds on top of the
/// xsend and xrecv calls in order to send and receive length-prefixed messages as vectors.
/// The length-prefixed messages are sent in chunks of `CHUNK_LENGTH` bytes.
/// See the comm module in the for the corresponding implementations in the V-App SDK and in
/// the V-App client SDK.

/// ACK is a single-byte acknowledgment message.
pub const ACK: [u8; 1] = [0x42];

/// The length of each chunk of data to be sent or received when calling xrecv/xsend.
pub const CHUNK_LENGTH: usize = 256;
