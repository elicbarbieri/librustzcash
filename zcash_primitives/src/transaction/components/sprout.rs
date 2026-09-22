//! Structs representing the components within Zcash transactions.

use alloc::vec::Vec;
use corez::io::{self, Read, Write};
use zcash_encoding::{CompactSize, Vector};

use super::GROTH_PROOF_SIZE;
use zcash_protocol::value::{ZatBalance, Zatoshis};

/// Size in bytes of a BCTV14 ("PHGR") proof: π_A + π_A' + π_B + π_B' + π_C + π_C' + π_K + π_H
pub const PHGR_PROOF_SIZE: usize = 33 + 33 + 65 + 33 + 33 + 33 + 33 + 33;

/// Number of notes a JoinSplit spends
pub const ZC_NUM_JS_INPUTS: usize = 2;

/// Number of notes a JoinSplit creates
pub const ZC_NUM_JS_OUTPUTS: usize = 2;

/// Size in bytes of a Sprout note ciphertext
pub const NOTE_CIPHERTEXT_SIZE: usize = 601;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    pub joinsplits: Vec<JsDescription>,
    pub joinsplit_pubkey: [u8; 32],
    pub joinsplit_sig: [u8; 64],
}

impl Bundle {
    /// The value balance for the bundle. When this is positive,
    /// its value is added to the transparent value pool; when it
    /// is negative, its value is subtracted from the transparent
    /// value pool.
    pub fn value_balance(&self) -> Option<ZatBalance> {
        self.joinsplits
            .iter()
            .try_fold(ZatBalance::zero(), |total, js| total + js.net_value())
    }
}

/// Reads the `nJoinSplit`, `vJoinSplit`, `joinSplitPubKey` and `joinSplitSig` fields
/// (`None` if no JoinSplits; `use_groth` = v4)
pub(crate) fn read_bundle<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Option<Bundle>> {
    let joinsplits = Vector::read(&mut reader, |r| JsDescription::read(r, use_groth))?;
    if joinsplits.is_empty() {
        return Ok(None);
    }

    let mut joinsplit_pubkey = [0; 32];
    reader.read_exact(&mut joinsplit_pubkey)?;
    let mut joinsplit_sig = [0; 64];
    reader.read_exact(&mut joinsplit_sig)?;

    Ok(Some(Bundle {
        joinsplits,
        joinsplit_pubkey,
        joinsplit_sig,
    }))
}

/// Writes the fields [`read_bundle`] reads
pub(crate) fn write_bundle<W: Write>(mut writer: W, bundle: Option<&Bundle>) -> io::Result<()> {
    match bundle {
        Some(bundle) => {
            Vector::write(&mut writer, &bundle.joinsplits, |w, e| e.write(w))?;
            writer.write_all(&bundle.joinsplit_pubkey)?;
            writer.write_all(&bundle.joinsplit_sig)
        }
        None => CompactSize::write(&mut writer, 0),
    }
}

/// A JoinSplit proof
#[derive(Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum SproutProof {
    /// Groth16 (v4 transactions)
    Groth([u8; GROTH_PROOF_SIZE]),
    /// BCTV14 (v2 & v3 transactions)
    PHGR([u8; PHGR_PROOF_SIZE]),
}

impl core::fmt::Debug for SproutProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        match self {
            SproutProof::Groth(_) => write!(f, "SproutProof::Groth"),
            SproutProof::PHGR(_) => write!(f, "SproutProof::PHGR"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct JsDescription {
    pub(crate) vpub_old: ZatBalance,
    pub(crate) vpub_new: ZatBalance,
    pub(crate) anchor: [u8; 32],
    pub(crate) nullifiers: [[u8; 32]; ZC_NUM_JS_INPUTS],
    pub(crate) commitments: [[u8; 32]; ZC_NUM_JS_OUTPUTS],
    pub(crate) ephemeral_key: [u8; 32],
    pub(crate) random_seed: [u8; 32],
    pub(crate) macs: [[u8; 32]; ZC_NUM_JS_INPUTS],
    pub(crate) proof: SproutProof,
    pub(crate) ciphertexts: [[u8; NOTE_CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
}

impl core::fmt::Debug for JsDescription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "JSDescription(
                vpub_old = {:?}, vpub_new = {:?},
                anchor = {:?},
                nullifiers = {:?},
                commitments = {:?},
                ephemeral_key = {:?},
                random_seed = {:?},
                macs = {:?})",
            self.vpub_old,
            self.vpub_new,
            self.anchor,
            self.nullifiers,
            self.commitments,
            self.ephemeral_key,
            self.random_seed,
            self.macs
        )
    }
}

impl JsDescription {
    /// Constructs a JoinSplit description (`vpub_old` & `vpub_new` non-negative, as on the wire)
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        vpub_old: Zatoshis,
        vpub_new: Zatoshis,
        anchor: [u8; 32],
        nullifiers: [[u8; 32]; ZC_NUM_JS_INPUTS],
        commitments: [[u8; 32]; ZC_NUM_JS_OUTPUTS],
        ephemeral_key: [u8; 32],
        random_seed: [u8; 32],
        macs: [[u8; 32]; ZC_NUM_JS_INPUTS],
        proof: SproutProof,
        ciphertexts: [[u8; NOTE_CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS],
    ) -> Self {
        JsDescription {
            vpub_old: vpub_old.into(),
            vpub_new: vpub_new.into(),
            anchor,
            nullifiers,
            commitments,
            ephemeral_key,
            random_seed,
            macs,
            proof,
            ciphertexts,
        }
    }

    pub fn read<R: Read>(mut reader: R, use_groth: bool) -> io::Result<Self> {
        // Consensus rule (§4.3): Canonical encoding is enforced here
        let vpub_old = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            ZatBalance::from_u64_le_bytes(tmp)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vpub_old out of range"))?;

        // Consensus rule (§4.3): Canonical encoding is enforced here
        let vpub_new = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp)?;
            ZatBalance::from_u64_le_bytes(tmp)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "vpub_new out of range"))?;

        // Consensus rule (§4.3): One of vpub_old and vpub_new being zero is
        // enforced by CheckTransactionWithoutProofVerification() in zcashd.

        let mut anchor = [0u8; 32];
        reader.read_exact(&mut anchor)?;

        let mut nullifiers = [[0u8; 32]; ZC_NUM_JS_INPUTS];
        nullifiers
            .iter_mut()
            .try_for_each(|nf| reader.read_exact(nf))?;

        let mut commitments = [[0u8; 32]; ZC_NUM_JS_OUTPUTS];
        commitments
            .iter_mut()
            .try_for_each(|cm| reader.read_exact(cm))?;

        // Consensus rule (§4.3): Canonical encoding is enforced by
        // ZCNoteDecryption::decrypt() in zcashd
        let mut ephemeral_key = [0u8; 32];
        reader.read_exact(&mut ephemeral_key)?;

        let mut random_seed = [0u8; 32];
        reader.read_exact(&mut random_seed)?;

        let mut macs = [[0u8; 32]; ZC_NUM_JS_INPUTS];
        macs.iter_mut().try_for_each(|mac| reader.read_exact(mac))?;

        let proof = if use_groth {
            // Consensus rules (§4.3):
            // - Canonical encoding is enforced in librustzcash_sprout_verify()
            // - Proof validity is enforced in librustzcash_sprout_verify()
            let mut proof = [0u8; GROTH_PROOF_SIZE];
            reader.read_exact(&mut proof)?;
            SproutProof::Groth(proof)
        } else {
            // Consensus rules (§4.3):
            // - Canonical encoding is enforced by PHGRProof in zcashd
            // - Proof validity is enforced by JSDescription::Verify() in zcashd
            let mut proof = [0u8; PHGR_PROOF_SIZE];
            reader.read_exact(&mut proof)?;
            SproutProof::PHGR(proof)
        };

        let mut ciphertexts = [[0u8; NOTE_CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS];
        ciphertexts
            .iter_mut()
            .try_for_each(|ct| reader.read_exact(ct))?;

        Ok(JsDescription {
            vpub_old,
            vpub_new,
            anchor,
            nullifiers,
            commitments,
            ephemeral_key,
            random_seed,
            macs,
            proof,
            ciphertexts,
        })
    }

    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.vpub_old.to_i64_le_bytes())?;
        writer.write_all(&self.vpub_new.to_i64_le_bytes())?;
        writer.write_all(&self.anchor)?;
        writer.write_all(&self.nullifiers[0])?;
        writer.write_all(&self.nullifiers[1])?;
        writer.write_all(&self.commitments[0])?;
        writer.write_all(&self.commitments[1])?;
        writer.write_all(&self.ephemeral_key)?;
        writer.write_all(&self.random_seed)?;
        writer.write_all(&self.macs[0])?;
        writer.write_all(&self.macs[1])?;

        match &self.proof {
            SproutProof::Groth(p) => writer.write_all(p)?,
            SproutProof::PHGR(p) => writer.write_all(p)?,
        }

        writer.write_all(&self.ciphertexts[0])?;
        writer.write_all(&self.ciphertexts[1])
    }

    /// The net value for the JoinSplit. When this is positive,
    /// its value is added to the transparent value pool; when it
    /// is negative, its value is subtracted from the transparent
    /// value pool.
    pub fn net_value(&self) -> ZatBalance {
        (self.vpub_new - self.vpub_old).expect("difference is in range [-MAX_MONEY..=MAX_MONEY]")
    }

    /// Returns the value added to the Sprout pool by this JoinSplit.
    pub fn vpub_old(&self) -> ZatBalance {
        self.vpub_old
    }

    /// Returns the value removed from the Sprout pool by this JoinSplit.
    pub fn vpub_new(&self) -> ZatBalance {
        self.vpub_new
    }

    /// Returns the Sprout note commitment tree anchor for this JoinSplit.
    pub fn anchor(&self) -> &[u8; 32] {
        &self.anchor
    }

    /// Returns the nullifiers for the input notes of this JoinSplit.
    pub fn nullifiers(&self) -> &[[u8; 32]; ZC_NUM_JS_INPUTS] {
        &self.nullifiers
    }

    /// Returns the note commitments for the output notes of this JoinSplit.
    pub fn commitments(&self) -> &[[u8; 32]; ZC_NUM_JS_OUTPUTS] {
        &self.commitments
    }

    /// Returns the ephemeral key used to encrypt the output notes of this JoinSplit.
    pub fn ephemeral_key(&self) -> &[u8; 32] {
        &self.ephemeral_key
    }

    /// Returns the encrypted output notes of this JoinSplit.
    pub fn ciphertexts(&self) -> &[[u8; NOTE_CIPHERTEXT_SIZE]; ZC_NUM_JS_OUTPUTS] {
        &self.ciphertexts
    }

    /// Returns the proof of this JoinSplit.
    pub fn proof(&self) -> &SproutProof {
        &self.proof
    }

    /// Returns the random seed for this JoinSplit.
    pub fn random_seed(&self) -> &[u8; 32] {
        &self.random_seed
    }

    /// Returns the message authentication codes for this JoinSplit.
    pub fn macs(&self) -> &[[u8; 32]; ZC_NUM_JS_INPUTS] {
        &self.macs
    }

    /// Returns the Groth16 proof bytes for this JoinSplit, if it uses Groth16.
    /// Returns `None` for PHGR proofs (pre-Sapling).
    pub fn groth_proof_bytes(&self) -> Option<&[u8; GROTH_PROOF_SIZE]> {
        match &self.proof {
            SproutProof::Groth(bytes) => Some(bytes),
            SproutProof::PHGR(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use zcash_protocol::value::Zatoshis;

    use super::{
        Bundle, JsDescription, NOTE_CIPHERTEXT_SIZE, PHGR_PROOF_SIZE, SproutProof, read_bundle,
        write_bundle,
    };
    use crate::transaction::components::GROTH_PROOF_SIZE;

    fn joinsplit(proof: SproutProof) -> JsDescription {
        JsDescription::from_parts(
            Zatoshis::from_u64(5).unwrap(),
            Zatoshis::ZERO,
            [1; 32],
            [[2; 32], [3; 32]],
            [[4; 32], [5; 32]],
            [6; 32],
            [7; 32],
            [[8; 32], [9; 32]],
            proof,
            [[10; NOTE_CIPHERTEXT_SIZE], [11; NOTE_CIPHERTEXT_SIZE]],
        )
    }

    /// Round-trips under both proof systems; no JoinSplits = a single zero count
    #[test]
    fn bundle_round_trips_from_parts() {
        for (proof, use_groth) in [
            (SproutProof::Groth([12; GROTH_PROOF_SIZE]), true),
            (SproutProof::PHGR([13; PHGR_PROOF_SIZE]), false),
        ] {
            let bundle = Bundle {
                joinsplits: alloc::vec![joinsplit(proof.clone()), joinsplit(proof)],
                joinsplit_pubkey: [14; 32],
                joinsplit_sig: [15; 64],
            };

            let mut encoding = Vec::new();
            write_bundle(&mut encoding, Some(&bundle)).unwrap();
            let read = read_bundle(&encoding[..], use_groth).unwrap();
            assert_eq!(read.as_ref(), Some(&bundle));
            assert_eq!(read.unwrap().value_balance(), bundle.value_balance());
        }

        let mut empty = Vec::new();
        write_bundle(&mut empty, None).unwrap();
        assert_eq!(empty, [0]);
        assert_eq!(read_bundle(&empty[..], true).unwrap(), None);
    }
}
