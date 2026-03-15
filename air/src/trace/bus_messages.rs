//! Shared bus message structs for encoding multiset/LogUp contributions.
//!
//! These types are generic over the field element type, enabling reuse across:
//! - **AIR constraints** (symbolic expressions): e.g. `BitwiseMessage<AB::Expr>`
//! - **Processor aux trace builders** (concrete field elements): e.g. `BitwiseMessage<Felt>`
//!
//! Each struct captures the data fields of a bus message and provides an `encode` method
//! that delegates to [`Challenges::encode`](super::Challenges::encode).

use core::{
    fmt,
    ops::{AddAssign, Mul},
};

use miden_core::field::PrimeCharacteristicRing;

use super::{Challenges, bus_interactions::{ACE_WIRING_BUS, CHIPLETS_BUS}};

// BITWISE CHIPLET MESSAGE
// ================================================================================================

/// Debug source for a [`BitwiseMessage`].
#[derive(Debug, Clone, Copy)]
pub enum BitwiseSource {
    /// Request from U32AND stack operation.
    U32And,
    /// Request from U32XOR stack operation.
    U32Xor,
    /// Response from bitwise chiplet.
    Chiplet,
}

impl fmt::Display for BitwiseSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U32And => f.write_str("u32and"),
            Self::U32Xor => f.write_str("u32xor"),
            Self::Chiplet => f.write_str("bitwise chiplet"),
        }
    }
}

/// A bitwise chiplet bus message (U32AND / U32XOR).
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2 * a + alpha^3 * b + alpha^4 * z`
///
/// The `source` field is metadata for debugging and is not part of the encoding.
pub struct BitwiseMessage<F> {
    pub op_label: F,
    pub a: F,
    pub b: F,
    pub z: F,
    pub source: BitwiseSource,
}

impl<F: Clone> BitwiseMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(
            CHIPLETS_BUS,
            [self.op_label.clone(), self.a.clone(), self.b.clone(), self.z.clone()],
        )
    }
}

impl<F: fmt::Display> fmt::Display for BitwiseMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ op_label: {}, a: {}, b: {}, z: {} }}",
            self.op_label, self.a, self.b, self.z
        )
    }
}

// MEMORY WORD MESSAGE
// ================================================================================================

/// Debug source for a [`MemoryWordMessage`].
#[derive(Debug, Clone, Copy)]
pub enum MemoryWordSource {
    /// Response from memory chiplet.
    Chiplet,
    /// MLOADW request.
    Mloadw,
    /// MSTOREW request.
    Mstorew,
    /// MSTREAM request (first word).
    Mstream1,
    /// MSTREAM request (second word).
    Mstream2,
    /// PIPE request (first word).
    Pipe1,
    /// PIPE request (second word).
    Pipe2,
    /// CRYPTOSTREAM read (first word).
    CryptoStreamRead1,
    /// CRYPTOSTREAM read (second word).
    CryptoStreamRead2,
    /// CRYPTOSTREAM write (first word).
    CryptoStreamWrite1,
    /// CRYPTOSTREAM write (second word).
    CryptoStreamWrite2,
    /// DYN request.
    Dyn,
    /// DYNCALL request.
    Dyncall,
    /// Memory word read for ACE.
    ReadWordAce,
    /// HORNEREXT evaluation request.
    HornerextEval,
}

impl fmt::Display for MemoryWordSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chiplet => f.write_str("memory chiplet"),
            Self::Mloadw => f.write_str("mloadw"),
            Self::Mstorew => f.write_str("mstorew"),
            Self::Mstream1 => f.write_str("mstream req 1"),
            Self::Mstream2 => f.write_str("mstream req 2"),
            Self::Pipe1 => f.write_str("pipe req 1"),
            Self::Pipe2 => f.write_str("pipe req 2"),
            Self::CryptoStreamRead1 => f.write_str("crypto_stream read 1"),
            Self::CryptoStreamRead2 => f.write_str("crypto_stream read 2"),
            Self::CryptoStreamWrite1 => f.write_str("crypto_stream write 1"),
            Self::CryptoStreamWrite2 => f.write_str("crypto_stream write 2"),
            Self::Dyn => f.write_str("dyn"),
            Self::Dyncall => f.write_str("dyncall"),
            Self::ReadWordAce => f.write_str("read word ACE"),
            Self::HornerextEval => f.write_str("hornerext_eval_* req"),
        }
    }
}

/// A memory word bus message.
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2 * ctx + alpha^3 * addr
///           + alpha^4 * clk + alpha^5..8 * word[0..3]`
pub struct MemoryWordMessage<F> {
    pub op_label: F,
    pub ctx: F,
    pub addr: F,
    pub clk: F,
    pub word: [F; 4],
    pub source: MemoryWordSource,
}

impl<F: Clone> MemoryWordMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(CHIPLETS_BUS, [
            self.op_label.clone(),
            self.ctx.clone(),
            self.addr.clone(),
            self.clk.clone(),
            self.word[0].clone(),
            self.word[1].clone(),
            self.word[2].clone(),
            self.word[3].clone(),
        ])
    }
}

impl<F: fmt::Display + fmt::Debug> fmt::Display for MemoryWordMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ op_label: {}, ctx: {}, addr: {}, clk: {}, word: {:?} }}",
            self.op_label, self.ctx, self.addr, self.clk, self.word
        )
    }
}

// MEMORY ELEMENT MESSAGE
// ================================================================================================

/// Debug source for a [`MemoryElementMessage`].
#[derive(Debug, Clone, Copy)]
pub enum MemoryElementSource {
    /// Response from memory chiplet (element access).
    Chiplet,
    /// MLOAD request.
    Mload,
    /// MSTORE request.
    Mstore,
    /// FMP initialization write.
    FmpInit,
    /// ACE chiplet element read.
    AceRead,
    /// HORNERBASE evaluation point read.
    Hornerbase,
}

impl fmt::Display for MemoryElementSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chiplet => f.write_str("memory chiplet"),
            Self::Mload => f.write_str("mload"),
            Self::Mstore => f.write_str("mstore"),
            Self::FmpInit => f.write_str("fmp init"),
            Self::AceRead => f.write_str("ace read element"),
            Self::Hornerbase => f.write_str("hornerbase"),
        }
    }
}

/// A memory element bus message.
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2 * ctx + alpha^3 * addr
///           + alpha^4 * clk + alpha^5 * element`
pub struct MemoryElementMessage<F> {
    pub op_label: F,
    pub ctx: F,
    pub addr: F,
    pub clk: F,
    pub element: F,
    pub source: MemoryElementSource,
}

impl<F: Clone> MemoryElementMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(CHIPLETS_BUS, [
            self.op_label.clone(),
            self.ctx.clone(),
            self.addr.clone(),
            self.clk.clone(),
            self.element.clone(),
        ])
    }
}

impl<F: fmt::Display> fmt::Display for MemoryElementMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ op_label: {}, ctx: {}, addr: {}, clk: {}, element: {} }}",
            self.op_label, self.ctx, self.addr, self.clk, self.element
        )
    }
}

// ACE CHIPLET MESSAGE
// ================================================================================================

/// Debug source for an [`AceMessage`].
#[derive(Debug, Clone, Copy)]
pub enum AceSource {
    /// Request from ACE stack operation.
    Request,
    /// Response from ACE chiplet.
    Chiplet,
}

impl fmt::Display for AceSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => f.write_str("ace request"),
            Self::Chiplet => f.write_str("ace response"),
        }
    }
}

/// An ACE chiplet bus message.
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2 * clk + alpha^3 * ctx
///           + alpha^4 * ptr + alpha^5 * num_read_rows + alpha^6 * num_eval_rows`
pub struct AceMessage<F> {
    pub op_label: F,
    pub clk: F,
    pub ctx: F,
    pub ptr: F,
    pub num_read_rows: F,
    pub num_eval_rows: F,
    pub source: AceSource,
}

impl<F: Clone> AceMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(CHIPLETS_BUS, [
            self.op_label.clone(),
            self.clk.clone(),
            self.ctx.clone(),
            self.ptr.clone(),
            self.num_read_rows.clone(),
            self.num_eval_rows.clone(),
        ])
    }
}

impl<F: fmt::Display> fmt::Display for AceMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ op_label: {}, clk: {}, ctx: {}, ptr: {}, num_read_rows: {}, num_eval_rows: {} }}",
            self.op_label, self.clk, self.ctx, self.ptr, self.num_read_rows, self.num_eval_rows
        )
    }
}

// KERNEL ROM MESSAGE
// ================================================================================================

/// Debug source for a [`KernelRomMessage`].
#[derive(Debug, Clone, Copy)]
pub enum KernelRomSource {
    /// Response to SYSCALL from decoder.
    Call,
    /// Response to verifier/public input init.
    Init,
}

impl fmt::Display for KernelRomSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call => f.write_str("kernel rom"),
            Self::Init => f.write_str("kernel rom init"),
        }
    }
}

/// A kernel ROM chiplet bus message.
///
/// Encodes: `bus_prefix[CHIPLETS_BUS] + alpha^1 * label + alpha^2..5 * digest[0..3]`
pub struct KernelRomMessage<F> {
    pub op_label: F,
    pub kernel_proc_digest: [F; 4],
    pub source: KernelRomSource,
}

impl<F: Clone> KernelRomMessage<F> {
    /// Encodes this message against the given challenge set.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(CHIPLETS_BUS, [
            self.op_label.clone(),
            self.kernel_proc_digest[0].clone(),
            self.kernel_proc_digest[1].clone(),
            self.kernel_proc_digest[2].clone(),
            self.kernel_proc_digest[3].clone(),
        ])
    }
}

impl<F: fmt::Display + fmt::Debug> fmt::Display for KernelRomMessage<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ label: {}, proc digest: {:?} }}", self.op_label, self.kernel_proc_digest)
    }
}

// ACE WIRING BUS MESSAGE
// ================================================================================================

/// An ACE wiring bus message (wire value for the LogUp wiring relation).
///
/// Each wire carries an identifier and a two-element extension field value.
/// The clock cycle (`clk`) and context (`ctx`) are passed to [`encode`](Self::encode)
/// separately since they are constant across all wires within a single circuit evaluation.
///
/// Encodes: `bus_prefix[ACE_WIRING_BUS] + alpha^1 * clk + alpha^2 * ctx
///            + alpha^3 * id + alpha^4 * v0 + alpha^5 * v1`
pub struct AceWireMessage<F> {
    pub id: F,
    pub v0: F,
    pub v1: F,
}

impl<F> AceWireMessage<F> {
    /// Creates an `AceWireMessage` from a `[F; 3]` array of `[id, v0, v1]`.
    pub fn from_array(wire: [F; 3]) -> Self {
        let [id, v0, v1] = wire;
        Self { id, v0, v1 }
    }
}

impl<F: Clone> AceWireMessage<F> {
    /// Encodes this wire message with the given clock and context metadata.
    pub fn encode<EF>(&self, challenges: &Challenges<EF>, clk: F, ctx: F) -> EF
    where
        EF: PrimeCharacteristicRing + Mul<F, Output = EF> + AddAssign,
    {
        challenges.encode(
            ACE_WIRING_BUS,
            [clk, ctx, self.id.clone(), self.v0.clone(), self.v1.clone()],
        )
    }
}
