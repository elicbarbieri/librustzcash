//! Transaction whose Sapling & Orchard-protocol points are left compressed (bytes tier)

use core::fmt;
use core::ops::Deref;

use blake2b_simd::Hash as Blake2bHash;
use corez::io::{self, Read, Write};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId},
    value::ZatBalance,
};

#[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
use zcash_protocol::value::Zatoshis;

use super::{
    Transaction, TransactionData, TransactionParts, TxId, TxVersion,
    components::{orchard as orchard_serialization, sapling as sapling_serialization, sprout},
};
use crate::encoding::ReadBytesExt;
use ::transparent::{bundle as transparent, util::sha256d::HashReader};

type SaplingBytes = sapling::bundle::BundleBytes<sapling::bundle::Authorized, ZatBalance>;
type OrchardBytes = orchard::BundleBytes<orchard::bundle::Authorized, ZatBalance>;

/// A [`Transaction`] with its Sapling & Orchard-protocol descriptions left in compressed &
/// potentially non-canonical encodings.
///
/// [`CompressedTransaction::decompress`] must be used to decompress & check point rules
#[derive(Debug, Clone)]
pub struct CompressedTransaction {
    txid: TxId,
    data: CompressedTransactionData,
}

/// The fields of a [`CompressedTransaction`]
#[derive(Debug, Clone)]
pub struct CompressedTransactionData {
    version: TxVersion,
    consensus_branch_id: BranchId,
    lock_time: u32,
    expiry_height: BlockHeight,
    transparent_bundle: Option<transparent::Bundle<transparent::Authorized>>,
    sprout_bundle: Option<sprout::Bundle>,
    sapling_bundle: Option<SaplingBytes>,
    orchard_bundle: Option<OrchardBytes>,
    ironwood_bundle: Option<OrchardBytes>,
}

/// Bundle containing a description that breaks a point rule
///
/// Returned by [`CompressedTransaction::decompress`]
#[derive(Debug)]
#[non_exhaustive]
pub enum DecompressionError {
    Sapling(sapling::bundle::BundleDecompressionError),
    Orchard(orchard::bundle::BundleDecompressionError),
    Ironwood(orchard::bundle::BundleDecompressionError),
}

impl fmt::Display for DecompressionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompressionError::Sapling(e) => write!(f, "Sapling bundle: {e}"),
            DecompressionError::Orchard(e) => write!(f, "Orchard bundle: {e}"),
            DecompressionError::Ironwood(e) => write!(f, "Ironwood bundle: {e}"),
        }
    }
}

impl core::error::Error for DecompressionError {}

impl Deref for CompressedTransaction {
    type Target = CompressedTransactionData;

    fn deref(&self) -> &CompressedTransactionData {
        &self.data
    }
}

impl CompressedTransactionData {
    /// Constructs v1–v5 transaction data, as [`TransactionData::from_parts`] does
    ///
    /// v6: use [`CompressedTransactionData::from_parts_v6`]
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        version: TxVersion,
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<transparent::Authorized>>,
        sprout_bundle: Option<sprout::Bundle>,
        sapling_bundle: Option<SaplingBytes>,
        orchard_bundle: Option<OrchardBytes>,
    ) -> Self {
        CompressedTransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle: None,
        }
    }

    /// Constructs v6 transaction data, as [`TransactionData::from_parts_v6`] does
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts_v6(
        consensus_branch_id: BranchId,
        lock_time: u32,
        expiry_height: BlockHeight,
        transparent_bundle: Option<transparent::Bundle<transparent::Authorized>>,
        sapling_bundle: Option<SaplingBytes>,
        orchard_bundle: Option<OrchardBytes>,
        ironwood_bundle: Option<OrchardBytes>,
    ) -> Self {
        CompressedTransactionData {
            version: TxVersion::V6,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle,
            sprout_bundle: None,
            sapling_bundle,
            orchard_bundle,
            ironwood_bundle,
        }
    }

    /// Computes the txid, without decompressing any point
    ///
    /// Fails when [`TransactionParts::txid`] does
    pub fn freeze(self) -> io::Result<CompressedTransaction> {
        let txid = self.parts().txid()?;
        Ok(CompressedTransaction { txid, data: self })
    }

    /// Returns the transaction version
    pub fn version(&self) -> TxVersion {
        self.version
    }

    /// Returns the consensus branch ID this transaction was created for
    pub fn consensus_branch_id(&self) -> BranchId {
        self.consensus_branch_id
    }

    /// Returns the lock time
    pub fn lock_time(&self) -> u32 {
        self.lock_time
    }

    /// Returns the height after which this transaction expires
    pub fn expiry_height(&self) -> BlockHeight {
        self.expiry_height
    }

    /// Returns the transparent bundle
    pub fn transparent_bundle(&self) -> Option<&transparent::Bundle<transparent::Authorized>> {
        self.transparent_bundle.as_ref()
    }

    /// Returns the Sprout bundle
    pub fn sprout_bundle(&self) -> Option<&sprout::Bundle> {
        self.sprout_bundle.as_ref()
    }

    /// Returns the Sapling bundle
    pub fn sapling_bundle(&self) -> Option<&SaplingBytes> {
        self.sapling_bundle.as_ref()
    }

    /// Returns the Orchard bundle
    pub fn orchard_bundle(&self) -> Option<&OrchardBytes> {
        self.orchard_bundle.as_ref()
    }

    /// Returns the Ironwood bundle
    pub fn ironwood_bundle(&self) -> Option<&OrchardBytes> {
        self.ironwood_bundle.as_ref()
    }

    /// Borrows the fields as a [`TransactionParts`], for encoding & digesting
    pub fn parts(&self) -> TransactionParts<'_, SaplingBytes, OrchardBytes> {
        TransactionParts {
            version: self.version,
            consensus_branch_id: self.consensus_branch_id,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            transparent_bundle: self.transparent_bundle.as_ref(),
            sprout_bundle: self.sprout_bundle.as_ref(),
            sapling_bundle: self.sapling_bundle.as_ref(),
            orchard_bundle: self.orchard_bundle.as_ref(),
            ironwood_bundle: self.ironwood_bundle.as_ref(),
        }
    }
}

impl CompressedTransaction {
    /// Returns the txid, computed at parse or [`CompressedTransactionData::freeze`]
    pub fn txid(&self) -> TxId {
        self.txid
    }

    /// Consumes this transaction, returning its fields
    pub fn into_data(self) -> CompressedTransactionData {
        self.data
    }

    /// Returns the ZIP 244 authorizing-data commitment, without decompressing any point
    pub fn auth_commitment(&self) -> Blake2bHash {
        self.data.parts().auth_commitment()
    }

    /// Recovers the [`Transaction`], decompressing each bundle & checking the point rules
    ///
    /// - Sapling via [`sapling::bundle::BundleBytes::decompress`]
    /// - Orchard, then Ironwood, via [`orchard::BundleBytes::decompress`]
    ///
    /// Returns the first bundle's error, in that order. The txid carries over (defined over
    /// the encodings).
    pub fn decompress(self) -> Result<Transaction, DecompressionError> {
        let d = self.data;
        Ok(Transaction {
            txid: self.txid,
            data: TransactionData {
                version: d.version,
                consensus_branch_id: d.consensus_branch_id,
                lock_time: d.lock_time,
                expiry_height: d.expiry_height,
                // No transaction format encodes a ZIP 233 amount
                #[cfg(all(feature = "zip-233", zcash_unstable = "zip233"))]
                zip233_amount: Zatoshis::ZERO,
                transparent_bundle: d.transparent_bundle,
                sprout_bundle: d.sprout_bundle,
                sapling_bundle: d
                    .sapling_bundle
                    .map(|b| b.decompress().map_err(DecompressionError::Sapling))
                    .transpose()?,
                orchard_bundle: d
                    .orchard_bundle
                    .map(|b| b.decompress().map_err(DecompressionError::Orchard))
                    .transpose()?,
                ironwood_bundle: d
                    .ironwood_bundle
                    .map(|b| b.decompress().map_err(DecompressionError::Ironwood))
                    .transpose()?,
            },
        })
    }

    /// Writes the canonical encoding of this transaction
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        self.data.parts().write(writer)
    }

    /// Decodes a transaction, checking every rule that needs no curve arithmetic, & computes
    /// the txid. This parse operation does not check point rules.
    /// [`CompressedTransaction::decompress`] must be used to check the point rules.
    ///
    /// - `consensus_branch_id` used only for v1–v4 (v5+ encode their own)
    pub fn read<R: Read>(reader: R, consensus_branch_id: BranchId) -> io::Result<Self> {
        let mut reader = HashReader::new(reader);

        let version = TxVersion::read(&mut reader)?;
        match version {
            TxVersion::Sprout(_) | TxVersion::V3 | TxVersion::V4 => {
                Self::read_v4(reader, version, consensus_branch_id)
            }
            TxVersion::V5 => Self::read_v5(reader.into_base_reader(), version),
            TxVersion::V6 => Self::read_v6(reader.into_base_reader(), version),
            #[cfg(zcash_unstable = "nutachyon")]
            TxVersion::V7 => Self::read_v6(reader.into_base_reader(), version),
        }
    }

    fn read_v4<R: Read>(
        mut reader: HashReader<R>,
        version: TxVersion,
        consensus_branch_id: BranchId,
    ) -> io::Result<Self> {
        let transparent_bundle = Transaction::read_transparent(&mut reader)?;

        let lock_time = reader.read_u32_le()?;
        let expiry_height: BlockHeight = if version.has_overwinter() {
            reader.read_u32_le()?.into()
        } else {
            0u32.into()
        };

        let (value_balance, shielded_spends, shielded_outputs) =
            sapling_serialization::read_v4_components(&mut reader, version.has_sapling())?;

        let sprout_bundle = if version.has_sprout() {
            sprout::read_bundle(&mut reader, version.has_sapling())?
        } else {
            None
        };

        let binding_sig = if version.has_sapling()
            && !(shielded_spends.is_empty() && shielded_outputs.is_empty())
        {
            let mut sig = [0; 64];
            reader.read_exact(&mut sig)?;
            Some(redjubjub::Signature::from(sig))
        } else {
            None
        };

        let mut txid = [0; 32];
        let hash_bytes = reader.into_hash();
        txid.copy_from_slice(&hash_bytes);

        Ok(CompressedTransaction {
            txid: TxId::from_bytes(txid),
            data: CompressedTransactionData {
                version,
                consensus_branch_id,
                lock_time,
                expiry_height,
                transparent_bundle,
                sprout_bundle,
                sapling_bundle: binding_sig.and_then(|binding_sig| {
                    sapling::bundle::BundleBytes::from_parts(
                        shielded_spends,
                        shielded_outputs,
                        value_balance,
                        sapling::bundle::Authorized { binding_sig },
                    )
                }),
                orchard_bundle: None,
                ironwood_bundle: None,
            },
        })
    }

    fn read_v5<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Transaction::read_header_fragment(&mut reader)?;

        let data = CompressedTransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle: Transaction::read_transparent(&mut reader)?,
            sprout_bundle: None,
            sapling_bundle: sapling_serialization::read_v5_bundle_bytes(&mut reader)?,
            orchard_bundle: orchard_serialization::read_v5_bundle_bytes(
                &mut reader,
                consensus_branch_id,
            )?,
            ironwood_bundle: None,
        };

        data.freeze()
    }

    fn read_v6<R: Read>(mut reader: R, version: TxVersion) -> io::Result<Self> {
        let (consensus_branch_id, lock_time, expiry_height) =
            Transaction::read_header_fragment(&mut reader)?;

        let data = CompressedTransactionData {
            version,
            consensus_branch_id,
            lock_time,
            expiry_height,
            transparent_bundle: Transaction::read_transparent(&mut reader)?,
            sprout_bundle: None,
            sapling_bundle: sapling_serialization::read_v5_bundle_bytes(&mut reader)?,
            orchard_bundle: orchard_serialization::read_v6_bundle_bytes(
                &mut reader,
                consensus_branch_id,
                orchard::ValuePool::Orchard,
            )?,
            ironwood_bundle: orchard_serialization::read_v6_bundle_bytes(
                &mut reader,
                consensus_branch_id,
                orchard::ValuePool::Ironwood,
            )?,
        };

        data.freeze()
    }
}

impl Transaction {
    /// Converts to [`CompressedTransaction`], forgetting the invariants enforced by
    /// [`Transaction`].
    ///
    /// Infallible: a [`Transaction`] cannot hold a point that fails to encode
    pub fn compress(self) -> CompressedTransaction {
        let d = self.data;
        CompressedTransaction {
            txid: self.txid,
            data: CompressedTransactionData {
                version: d.version,
                consensus_branch_id: d.consensus_branch_id,
                lock_time: d.lock_time,
                expiry_height: d.expiry_height,
                transparent_bundle: d.transparent_bundle,
                sprout_bundle: d.sprout_bundle,
                sapling_bundle: d.sapling_bundle.map(sapling::Bundle::compress),
                orchard_bundle: d.orchard_bundle.map(orchard::Bundle::compress),
                ironwood_bundle: d.ironwood_bundle.map(orchard::Bundle::compress),
            },
        }
    }
}
