//! Bounded local execution evidence, independent of code and private advice.
//!
//! The caller supplies the descriptor and native policies. JSON merely repeats the expected
//! identities and supplies exact v1 node preimages/child slots. Selective membership does not
//! authorize a root, establish global key uniqueness, or qualify a proof/publication profile.

use std::{
    alloc::Layout,
    fmt,
    io::Read,
    marker::PhantomData,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use miden_core::{
    Felt, Word,
    program::{EnvNode, EnvironmentRoot, ExecutionTarget, ProcedureKey},
};
use miden_processor::{
    EnvironmentSourceError, EnvironmentTraceLimits, EnvironmentWitnessRequest,
    EnvironmentWitnessSource, OpeningLimits, OpeningStep, ResolutionLimits, ResolutionWitness,
};
use serde::{
    Deserialize,
    de::{DeserializeSeed, SeqAccess, Visitor},
};
use serde_json::value::RawValue;

/// Explicit local input/source limits. No deployment defaults are supplied.
///
/// Retained storage accounts source/per-host payload bodies and Vec capacities for records,
/// encoded steps and preimage bytes.
/// Preparation additionally covers input/parser/error buffers and sequential native path/hash
/// scratch. Requests are checked before reservation and returned capacities before publication.
/// Allocator excess beyond requests/metadata, Arc headers, fixed stack and RSS are excluded.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionInputLimits {
    pub max_file_bytes: usize,
    pub max_openings: usize,
    pub max_steps: usize,
    pub max_encoded_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_prepare_peak_bytes: usize,
    /// Every get attempt counts, including wrong-root and missing-key requests.
    /// Applies separately to each source() host budget; Arc clones share that counter.
    pub max_requests: usize,
}

#[derive(Debug)]
pub enum ExecutionInputError {
    Limit {
        resource: &'static str,
        maximum: usize,
        actual: usize,
    },
    Invalid(String),
    Overflow,
    Allocation,
    Io(std::io::Error),
}

impl fmt::Display for ExecutionInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit { resource, maximum, actual } => {
                write!(f, "execution input {resource} limit exceeded: {actual} > {maximum}")
            },
            Self::Invalid(message) => f.write_str(message),
            Self::Overflow => f.write_str("execution input length overflow"),
            Self::Allocation => f.write_str("execution input allocation failed"),
            Self::Io(error) => write!(f, "execution input file: {error}"),
        }
    }
}
impl std::error::Error for ExecutionInputError {}
type Result<T> = std::result::Result<T, ExecutionInputError>;

fn invalid(message: impl fmt::Display) -> ExecutionInputError {
    ExecutionInputError::Invalid(message.to_string())
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(ExecutionInputError::Overflow)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(ExecutionInputError::Overflow)
}
fn limit(resource: &'static str, actual: usize, maximum: usize) -> Result<()> {
    if actual > maximum {
        Err(ExecutionInputError::Limit { resource, maximum, actual })
    } else {
        Ok(())
    }
}
fn array_bytes<T>(count: usize) -> Result<usize> {
    Layout::array::<T>(count)
        .map(|layout| layout.size())
        .map_err(|_| ExecutionInputError::Overflow)
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    array_bytes::<T>(count)?;
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| ExecutionInputError::Allocation)?;
    Ok(result)
}

// All strings are unescaped ASCII: field names, exact Words and hexadecimal node records.
// This excludes serde's escaped-string scratch allocation; depth bounds RawValue's container
// stack too. The input-sized parser/error allowance is charged even for rejected documents.
fn parser_charge(bytes: usize) -> Result<usize> {
    add(mul(bytes, 8)?, 4096)
}
fn lexical_preflight(bytes: &[u8]) -> Result<()> {
    let mut quoted = false;
    let mut depth = 0usize;
    for &byte in bytes {
        if !byte.is_ascii() || byte == b'\\' || (quoted && (byte < 0x20 || byte == 0x7f)) {
            return Err(invalid("execution input requires unescaped ASCII JSON strings"));
        }
        if byte == b'"' {
            quoted = !quoted;
        } else if !quoted {
            match byte {
                b'[' | b'{' => {
                    depth = add(depth, 1)?;
                    limit("JSON depth", depth, 8)?;
                },
                b']' | b'}' => {
                    depth = depth
                        .checked_sub(1)
                        .ok_or_else(|| invalid("unbalanced execution input JSON"))?;
                },
                _ => {},
            }
        }
    }
    if quoted || depth != 0 {
        return Err(invalid("unbalanced execution input JSON"));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    version: u8,
    entry_key: &'a str,
    environment_root: &'a str,
    #[serde(borrow)]
    openings: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<'a> {
    key: &'a str,
    #[serde(borrow)]
    steps: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step<'a> {
    node: &'a str,
    // deserialize_with intentionally makes the nullable field REQUIRED (no default).
    #[serde(deserialize_with = "selected_child")]
    selected_child: Option<usize>,
}
fn selected_child<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<usize>, D::Error> {
    Option::<usize>::deserialize(d)
}
fn word(value: &str) -> Result<Word> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err(invalid("execution identity must be an exact 0x-prefixed canonical Word"));
    }
    Word::try_from(value).map_err(invalid)
}
fn node_hex(value: &str) -> Result<&str> {
    let hex = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid("node preimage requires 0x-prefixed hex"))?;
    if !hex.len().is_multiple_of(2) {
        return Err(invalid("node hex must contain complete bytes"));
    }
    Ok(hex)
}

// Streaming borrowed DTOs: no Vec of all raw JSON items and no per-record String allocations.
fn each<'de, T: Deserialize<'de>, F: FnMut(T) -> Result<()>>(
    raw: &'de RawValue,
    mut consume: F,
) -> Result<()> {
    struct Array<'a, T, F> {
        consume: &'a mut F,
        failure: &'a mut Option<ExecutionInputError>,
        marker: PhantomData<T>,
    }
    impl<'de, T: Deserialize<'de>, F: FnMut(T) -> Result<()>> Visitor<'de> for Array<'_, T, F> {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an execution input array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> std::result::Result<(), A::Error> {
            while let Some(value) = array.next_element::<T>()? {
                if let Err(error) = (self.consume)(value) {
                    *self.failure = Some(error);
                    return Err(serde::de::Error::custom("invalid execution evidence"));
                }
            }
            Ok(())
        }
    }
    impl<'de, T: Deserialize<'de>, F: FnMut(T) -> Result<()>> DeserializeSeed<'de> for Array<'_, T, F> {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<(), D::Error> {
            d.deserialize_seq(self)
        }
    }
    let mut failure = None;
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    let decoded = Array::<T, _> {
        consume: &mut consume,
        failure: &mut failure,
        marker: PhantomData,
    }
    .deserialize(&mut decoder);
    if let Some(error) = failure {
        return Err(error);
    }
    decoded.map_err(invalid)?;
    decoder.end().map_err(invalid)
}

#[derive(Default, Clone, Copy)]
struct Shape {
    steps: usize,
    encoded: usize,
}
fn shape(raw: &RawValue) -> Result<Shape> {
    let mut result = Shape::default();
    each::<Step<'_>, _>(raw, |step| {
        result.steps = add(result.steps, 1)?;
        result.encoded = add(result.encoded, node_hex(step.node)?.len() / 2)?;
        Ok(())
    })?;
    Ok(result)
}

struct EncodedStep {
    node: Vec<u8>,
    selected_child: Option<usize>,
}
struct StoredOpening {
    key: ProcedureKey,
    steps: Vec<EncodedStep>,
    stats: Stats,
}
struct SourceData {
    root: EnvironmentRoot,
    openings: Vec<StoredOpening>,
    retained: usize,
    limits: ExecutionInputLimits,
}

/// Successfully checked local evidence, with the caller's policies retained unchanged.
/// No code is loaded and no proof/publication authorization is implied.
pub struct AdmittedExecutionInputs {
    target: ExecutionTarget,
    resolution_limits: ResolutionLimits,
    trace_limits: EnvironmentTraceLimits,
    data: Arc<SourceData>,
}

impl AdmittedExecutionInputs {
    pub fn from_bytes(
        bytes: &[u8],
        target: ExecutionTarget,
        resolution_limits: ResolutionLimits,
        trace_limits: EnvironmentTraceLimits,
        limits: ExecutionInputLimits,
    ) -> Result<Self> {
        Self::admit(bytes, bytes.len(), target, resolution_limits, trace_limits, limits)
    }

    pub fn read(
        path: impl AsRef<Path>,
        target: ExecutionTarget,
        resolution_limits: ResolutionLimits,
        trace_limits: EnvironmentTraceLimits,
        limits: ExecutionInputLimits,
    ) -> Result<Self> {
        let mut file = miden_core::serde::open_regular_file(path, limits.max_file_bytes)
            .map_err(ExecutionInputError::Io)?;
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let take = limits
                .max_file_bytes
                .saturating_sub(bytes.len())
                .saturating_add(1)
                .min(chunk.len());
            let read = file.read(&mut chunk[..take]).map_err(ExecutionInputError::Io)?;
            if read == 0 {
                break;
            }
            let next = add(bytes.len(), read)?;
            limit("file bytes", next, limits.max_file_bytes)?;
            limit("prepare peak bytes", parser_charge(next)?, limits.max_prepare_peak_bytes)?;
            bytes.try_reserve_exact(read).map_err(|_| ExecutionInputError::Allocation)?;
            limit(
                "prepare peak bytes",
                parser_charge(bytes.capacity())?,
                limits.max_prepare_peak_bytes,
            )?;
            bytes.extend_from_slice(&chunk[..read]);
        }
        Self::admit(&bytes, bytes.capacity(), target, resolution_limits, trace_limits, limits)
    }

    fn admit(
        bytes: &[u8],
        input_storage: usize,
        target: ExecutionTarget,
        resolution_limits: ResolutionLimits,
        trace_limits: EnvironmentTraceLimits,
        limits: ExecutionInputLimits,
    ) -> Result<Self> {
        limit("file bytes", bytes.len(), limits.max_file_bytes)?;
        let parser = parser_charge(input_storage)?;
        limit("prepare peak bytes", parser, limits.max_prepare_peak_bytes)?;
        lexical_preflight(bytes)?;
        let document: Document<'_> = serde_json::from_slice(bytes).map_err(invalid)?;
        if document.version != 1 {
            return Err(invalid("unsupported execution input version"));
        }
        let descriptor = target;
        if word(document.entry_key)? != *descriptor.entry_key().as_word()
            || word(document.environment_root)? != *descriptor.environment_root().as_word()
        {
            return Err(invalid(
                "execution input descriptor differs from caller expected descriptor",
            ));
        }
        let native = resolution_limits.opening_limits();
        let mut count = 0;
        let mut total = Shape::default();
        let mut max_native = 0;
        each::<Record<'_>, _>(document.openings, |record| {
            word(record.key)?;
            count = add(count, 1)?;
            limit("openings", count, limits.max_openings)?;
            let path = shape(record.steps)?;
            limit("opening nodes", path.steps, native.max_nodes)?;
            if path.steps == 0 {
                return Err(invalid("empty execution opening"));
            }
            limit("opening depth", path.steps - 1, native.max_depth)?;
            limit("opening encoded bytes", path.encoded, native.max_encoded_bytes)?;
            total.steps = add(total.steps, path.steps)?;
            total.encoded = add(total.encoded, path.encoded)?;
            limit("steps", total.steps, limits.max_steps)?;
            limit("encoded bytes", total.encoded, limits.max_encoded_bytes)?;
            // Encoded lengths bound all decoded List requests plus their largest hash scratch.
            max_native = max_native
                .max(add(array_bytes::<OpeningStep>(path.steps)?, mul(path.encoded, 2)?)?);
            Ok(())
        })?;
        let bookkeeping = add(size_of::<SourceData>(), size_of::<LocalSource>())?;
        let storage_request = add(
            bookkeeping,
            add(
                add(
                    array_bytes::<StoredOpening>(count)?,
                    array_bytes::<EncodedStep>(total.steps)?,
                )?,
                total.encoded,
            )?,
        )?;
        limit("retained bytes", storage_request, limits.max_retained_bytes)?;
        limit(
            "prepare peak bytes",
            add(add(parser, mul(storage_request, 2)?)?, max_native)?,
            limits.max_prepare_peak_bytes,
        )?;
        let mut openings = reserve::<StoredOpening>(count)?;
        let mut retained = add(bookkeeping, array_bytes::<StoredOpening>(openings.capacity())?)?;
        check_source_space(parser, retained, max_native, limits)?;
        each::<Record<'_>, _>(document.openings, |record| {
            let key = ProcedureKey::new(word(record.key)?);
            let path_shape = shape(record.steps)?;
            let path_request = array_bytes::<OpeningStep>(path_shape.steps)?;
            limit("opening storage bytes", path_request, native.max_storage_bytes)?;
            check_source_space(
                parser,
                add(retained, array_bytes::<EncodedStep>(path_shape.steps)?)?,
                path_request,
                limits,
            )?;
            let mut encoded = reserve::<EncodedStep>(path_shape.steps)?;
            retained = add(retained, array_bytes::<EncodedStep>(encoded.capacity())?)?;
            check_source_space(parser, retained, path_request, limits)?;
            let mut path = reserve::<OpeningStep>(path_shape.steps)?;
            let mut native_heap = array_bytes::<OpeningStep>(path.capacity())?;
            let mut list_children = 0usize;
            let mut max_scratch = 0;
            check_source_space(parser, retained, native_heap, limits)?;
            limit("opening storage bytes", native_heap, native.max_storage_bytes)?;
            each::<Step<'_>, _>(record.steps, |step| {
                let hex = node_hex(step.node)?;
                let length = hex.len() / 2;
                check_source_space(parser, add(retained, length)?, native_heap, limits)?;
                let mut node_bytes = reserve::<u8>(length)?;
                retained = add(retained, node_bytes.capacity())?;
                check_source_space(parser, retained, native_heap, limits)?;
                node_bytes.resize(length, 0);
                hex::decode_to_slice(hex, &mut node_bytes).map_err(invalid)?;
                if let Some(children) =
                    EnvNode::preflight_bytes(&node_bytes, native.max_encoded_bytes)
                        .map_err(invalid)?
                {
                    limit("opening List children", children, native.max_list_children)?;
                    list_children = add(list_children, children)?;
                    limit(
                        "opening total List children",
                        list_children,
                        native.max_total_list_children,
                    )?;
                    let requested = array_bytes::<EnvironmentRoot>(children)?;
                    max_scratch = max_scratch.max(array_bytes::<Felt>(mul(children, 4)?)?);
                    limit(
                        "opening storage bytes",
                        add(add(native_heap, requested)?, max_scratch)?,
                        native.max_storage_bytes,
                    )?;
                    check_source_space(
                        parser,
                        retained,
                        add(add(native_heap, requested)?, max_scratch)?,
                        limits,
                    )?;
                }
                let node =
                    EnvNode::from_bytes(&node_bytes, native.max_encoded_bytes).map_err(invalid)?;
                if let EnvNode::List(children) = &node {
                    native_heap =
                        add(native_heap, array_bytes::<EnvironmentRoot>(children.capacity())?)?;
                }
                limit(
                    "opening storage bytes",
                    add(native_heap, max_scratch)?,
                    native.max_storage_bytes,
                )?;
                check_source_space(parser, retained, add(native_heap, max_scratch)?, limits)?;
                path.push(OpeningStep {
                    node,
                    selected_child: step.selected_child,
                });
                encoded.push(EncodedStep {
                    node: node_bytes,
                    selected_child: step.selected_child,
                });
                Ok(())
            })?;
            let candidate = ResolutionWitness { path };
            let stats = Stats::of(&candidate)?;
            stats.check(native)?;
            check_source_space(parser, retained, stats.storage, limits)?;
            // Verify every supplied path; unavailable code is not relevant to membership.
            candidate.verify(descriptor.environment_root(), key, native).map_err(invalid)?;
            openings.push(StoredOpening { key, steps: encoded, stats });
            Ok(())
        })?;
        openings.sort_unstable_by_key(|opening| opening.key);
        if openings.windows(2).any(|pair| pair[0].key == pair[1].key) {
            return Err(invalid("duplicate execution opening key"));
        }
        if openings
            .binary_search_by_key(&descriptor.entry_key(), |opening| opening.key)
            .is_err()
        {
            return Err(invalid("entry opening is unavailable"));
        }
        Ok(Self {
            target,
            resolution_limits,
            trace_limits,
            data: Arc::new(SourceData {
                root: descriptor.environment_root(),
                openings,
                retained,
                limits,
            }),
        })
    }

    pub fn target(&self) -> ExecutionTarget {
        self.target
    }
    pub fn resolution_limits(&self) -> ResolutionLimits {
        self.resolution_limits
    }
    pub fn trace_limits(&self) -> EnvironmentTraceLimits {
        self.trace_limits
    }
    /// Each host gets a fresh request budget; clones of that Arc share the budget.
    pub fn source(&self) -> Arc<dyn EnvironmentWitnessSource> {
        Arc::new(LocalSource {
            data: self.data.clone(),
            requests: AtomicUsize::new(0),
        })
    }
}

fn check_source_space(
    parser: usize,
    retained: usize,
    native: usize,
    limits: ExecutionInputLimits,
) -> Result<()> {
    limit("retained bytes", retained, limits.max_retained_bytes)?;
    limit(
        "prepare peak bytes",
        add(add(parser, retained)?, native)?,
        limits.max_prepare_peak_bytes,
    )
}

#[derive(Clone, Copy)]
struct Stats {
    nodes: usize,
    depth: usize,
    max_list: usize,
    total_list: usize,
    encoded: usize,
    storage: usize,
}
impl Stats {
    fn of(candidate: &ResolutionWitness) -> Result<Self> {
        let mut result = Self {
            nodes: candidate.path.len(),
            depth: candidate.path.len().saturating_sub(1),
            max_list: 0,
            total_list: 0,
            encoded: 0,
            storage: array_bytes::<OpeningStep>(candidate.path.capacity())?,
        };
        let mut scratch = 0;
        for step in &candidate.path {
            result.encoded = add(result.encoded, step.node.encoded_len().map_err(invalid)?)?;
            if let EnvNode::List(children) = &step.node {
                result.max_list = result.max_list.max(children.len());
                result.total_list = add(result.total_list, children.len())?;
                result.storage =
                    add(result.storage, array_bytes::<EnvironmentRoot>(children.capacity())?)?;
                scratch = scratch.max(array_bytes::<Felt>(mul(children.len(), 4)?)?);
            }
        }
        result.storage = add(result.storage, scratch)?;
        Ok(result)
    }
    fn check(self, limits: OpeningLimits) -> Result<()> {
        for (name, actual, maximum) in [
            ("opening nodes", self.nodes, limits.max_nodes),
            ("opening depth", self.depth, limits.max_depth),
            ("opening List children", self.max_list, limits.max_list_children),
            ("opening total List children", self.total_list, limits.max_total_list_children),
            ("opening encoded bytes", self.encoded, limits.max_encoded_bytes),
            ("opening storage bytes", self.storage, limits.max_storage_bytes),
        ] {
            limit(name, actual, maximum)?;
        }
        Ok(())
    }
}

struct LocalSource {
    data: Arc<SourceData>,
    requests: AtomicUsize,
}
impl EnvironmentWitnessSource for LocalSource {
    fn get(
        &self,
        request: EnvironmentWitnessRequest,
    ) -> std::result::Result<Option<ResolutionWitness>, EnvironmentSourceError> {
        self.candidate(request)
            .map_err(|error| Box::new(error) as EnvironmentSourceError)
    }
}
impl LocalSource {
    fn candidate(&self, request: EnvironmentWitnessRequest) -> Result<Option<ResolutionWitness>> {
        self.requests
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < self.data.limits.max_requests).then(|| count.checked_add(1)).flatten()
            })
            .map_err(|_| invalid("execution source request limit exceeded"))?;
        if request.root != self.data.root {
            return Err(invalid("execution source root differs from request"));
        }
        let Ok(index) =
            self.data.openings.binary_search_by_key(&request.key, |opening| opening.key)
        else {
            return Ok(None);
        };
        let stored = &self.data.openings[index];
        // This precedes every allocation/copy/decoder call, including tighter native requests.
        stored.stats.check(request.limits)?;
        check_source_space(0, self.data.retained, stored.stats.storage, self.data.limits)?;
        let mut path = reserve::<OpeningStep>(stored.steps.len())?;
        let mut heap = array_bytes::<OpeningStep>(path.capacity())?;
        let mut scratch = 0;
        limit("opening storage bytes", heap, request.limits.max_storage_bytes)?;
        for step in &stored.steps {
            // Immutable admitted bytes have the cached shape, but still use the exact core codec.
            if let Some(children) =
                EnvNode::preflight_bytes(&step.node, request.limits.max_encoded_bytes)
                    .map_err(invalid)?
            {
                let requested = array_bytes::<EnvironmentRoot>(children)?;
                scratch = scratch.max(array_bytes::<Felt>(mul(children, 4)?)?);
                limit(
                    "opening storage bytes",
                    add(add(heap, requested)?, scratch)?,
                    request.limits.max_storage_bytes,
                )?;
                check_source_space(
                    0,
                    self.data.retained,
                    add(add(heap, requested)?, scratch)?,
                    self.data.limits,
                )?;
            }
            let node = EnvNode::from_bytes(&step.node, request.limits.max_encoded_bytes)
                .map_err(invalid)?;
            if let EnvNode::List(children) = &node {
                heap = add(heap, array_bytes::<EnvironmentRoot>(children.capacity())?)?;
            }
            limit("opening storage bytes", add(heap, scratch)?, request.limits.max_storage_bytes)?;
            check_source_space(0, self.data.retained, add(heap, scratch)?, self.data.limits)?;
            path.push(OpeningStep {
                node,
                selected_child: step.selected_child,
            });
        }
        let result = ResolutionWitness { path };
        Stats::of(&result)?.check(request.limits)?;
        // This remains an untrusted candidate; the consumer independently verifies it.
        Ok(Some(result))
    }
}
