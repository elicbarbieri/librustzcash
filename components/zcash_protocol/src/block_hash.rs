use alloc::string::{String, ToString};
use core::fmt;

use zcash_encoding::ReverseHex;

#[cfg(feature = "std")]
use memuse::DynamicUsage;

/// The identifier for a Zcash block.
///
/// This is the SHA-256d hash of the encoded block header.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash(pub [u8; 32]);

#[cfg(feature = "std")]
memuse::impl_no_dynamic_usage!(BlockHash);

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The (byte-flipped) hex string is more useful than the raw bytes, because we can
        // look that up in RPC methods and block explorers.
        let block_hash_str = self.to_string();
        f.debug_tuple("BlockHash").field(&block_hash_str).finish()
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl BlockHash {
    /// Constructs a [`BlockHash`] from the given slice.
    ///
    /// # Panics
    ///
    /// This function will panic if the slice is not exactly 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::try_from_slice(bytes).unwrap()
    }

    /// Constructs a [`BlockHash`] from the given slice.
    ///
    /// Returns `None` if `bytes` has any length other than 32
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut hash = [0; 32];
            hash.copy_from_slice(bytes);
            Some(BlockHash(hash))
        } else {
            None
        }
    }

    /// Encodes this block hash in its canonical hexadecimal representation.
    pub fn as_hex(&self) -> String {
        ReverseHex::encode(&self.0)
    }

    /// Parses a block hash from its canonical hexadecimal representation — the byte-reversed
    /// form produced by this type's [`Display`](fmt::Display) impl, as shown by block explorers
    /// and node RPCs. Returns `None` if the input is not exactly 64 hexadecimal digits.
    pub fn from_hex(s: &str) -> Option<Self> {
        ReverseHex::decode(s).map(BlockHash)
    }
}

#[cfg(test)]
mod tests {
    use super::BlockHash;
    use alloc::string::ToString;

    /// `from_hex` inverts `Display` exactly, and is NOT the inverse of hex-encoding the internal
    /// bytes: the two encodings are mutually byte-reversed, checked with an asymmetric pattern.
    #[test]
    fn hex_round_trips_through_display_in_byte_reversed_order() {
        let display = "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08";
        let hash = BlockHash::from_hex(display).unwrap();
        assert_eq!(hash.0[31], 0x00);
        assert_eq!(hash.0[0], 0x08);
        assert_eq!(hash.to_string(), display);
        assert_eq!(hash.as_hex(), display);

        assert_eq!(BlockHash::from_hex(&display[2..]), None);
        assert_eq!(BlockHash::from_hex(&display.replace('c', "g")), None);
    }
}
