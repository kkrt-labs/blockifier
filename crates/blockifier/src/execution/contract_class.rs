use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_lang_casm;
use cairo_lang_casm::hints::Hint;
use cairo_lang_sierra::program::Program as SierraProgram;
use cairo_lang_starknet_classes::casm_contract_class::{
    CasmContractClass, CasmContractEntryPoint, StarknetSierraCompilationError,
};
use cairo_lang_starknet_classes::contract_class::{
    ContractClass as SierraContractClass, ContractEntryPoints as SierraContractEntryPoints,
};
use cairo_lang_starknet_classes::NestedIntList;
use cairo_lang_utils::bigint::BigUintAsHex;
use cairo_vm::serde::deserialize_program::{
    ApTracking, FlowTrackingData, HintParams, ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, POSEIDON_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources;
use itertools::Itertools;
use num_traits::Num;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointOffset, EntryPointType,
    Program as DeprecatedProgram,
};

use super::execution_utils::{cairo_vm_to_sn_api_program, poseidon_hash_many_cost};
use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{self, CONSTRUCTOR_ENTRY_POINT_NAME};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::errors::{ContractClassError, PreExecutionError};
use crate::execution::execution_utils::{felt_to_stark_felt, sn_api_to_cairo_vm_program};
use crate::execution::native::utils::contract_entrypoint_to_entrypoint_selector;
use crate::fee::eth_gas_constants;
use crate::transaction::errors::TransactionExecutionError;

#[cfg(test)]
#[path = "contract_class_test.rs"]
pub mod test;

/// Represents a runnable Starknet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.

pub type ContractClassResult<T> = Result<T, ContractClassError>;

#[derive(Clone, Debug, Eq, PartialEq, derive_more::From, Serialize, Deserialize)]
pub enum ContractClass {
    V0(ContractClassV0),
    V1(ContractClassV1),
    V1Sierra(SierraContractClassV1),
}

impl ContractClass {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        match self {
            ContractClass::V0(class) => class.constructor_selector(),
            ContractClass::V1(class) => class.constructor_selector(),
            ContractClass::V1Sierra(class) => class.constructor_selector(),
        }
    }

    pub fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        match self {
            ContractClass::V0(class) => class.estimate_casm_hash_computation_resources(),
            ContractClass::V1(class) => class.estimate_casm_hash_computation_resources(),
            ContractClass::V1Sierra(_) => todo!("sierra estimate casm hash computation resources"),
        }
    }

    pub fn get_visited_segments(
        &self,
        visited_pcs: &HashSet<usize>,
    ) -> Result<Vec<usize>, TransactionExecutionError> {
        match self {
            ContractClass::V0(_) => {
                panic!("get_visited_segments is not supported for v0 contracts.")
            }
            ContractClass::V1(class) => class.get_visited_segments(visited_pcs),
            ContractClass::V1Sierra(_) => todo!("sierra visited segments"),
        }
    }

    pub fn bytecode_length(&self) -> usize {
        match self {
            ContractClass::V0(class) => class.bytecode_length(),
            ContractClass::V1(class) => class.bytecode_length(),
            ContractClass::V1Sierra(_) => todo!("sierra estimate casm hash computation resources"),
        }
    }
}

// V0.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ContractClassV0(pub Arc<ContractClassV0Inner>);
impl Deref for ContractClassV0 {
    type Target = ContractClassV0Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ContractClassV0 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    fn n_entry_points(&self) -> usize {
        self.entry_points_by_type.values().map(|vec| vec.len()).sum()
    }

    pub fn n_builtins(&self) -> usize {
        self.program.builtins_len()
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        let hashed_data_size = (constants::CAIRO0_ENTRY_POINT_STRUCT_SIZE * self.n_entry_points())
            + self.n_builtins()
            + self.bytecode_length()
            + 1; // Hinted class hash.
        // The hashed data size is approximately the number of hashes (invoked in hash chains).
        let n_steps = constants::N_STEPS_PER_PEDERSEN * hashed_data_size;

        ExecutionResources {
            n_steps,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(
                HASH_BUILTIN_NAME.to_string(),
                hashed_data_size,
            )]),
        }
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<ContractClassV0, ProgramError> {
        let contract_class: ContractClassV0Inner = serde_json::from_str(raw_contract_class)?;
        Ok(ContractClassV0(Arc::new(contract_class)))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct ContractClassV0Inner {
    #[serde(deserialize_with = "deserialize_program", serialize_with = "serialize_program")]
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPoint>>,
}

impl TryFrom<DeprecatedContractClass> for ContractClassV0 {
    type Error = ProgramError;

    fn try_from(class: DeprecatedContractClass) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(ContractClassV0Inner {
            program: sn_api_to_cairo_vm_program(class.program)?,
            entry_points_by_type: class.entry_points_by_type,
        })))
    }
}

// V1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractClassV1(pub Arc<ContractClassV1Inner>);
impl Deref for ContractClassV1 {
    type Target = ContractClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for ContractClassV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the ContractClassV1 instance to CasmContractClass
        let casm_contract_class: CasmContractClass = self
            .try_into()
            .map_err(|err: ProgramError| serde::ser::Error::custom(err.to_string()))?;

        // Serialize the JSON string to bytes
        casm_contract_class.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContractClassV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a JSON value
        let json_value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Convert into a JSON string
        let json_string = serde_json::to_string(&json_value)
            .map_err(|err| DeserializationError::custom(err.to_string()))?;

        // Use try_from_json_string to deserialize into ContractClassV1
        ContractClassV1::try_from_json_string(&json_string)
            .map_err(|err| DeserializationError::custom(err.to_string()))
    }
}

impl ContractClassV1 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.0.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    pub fn bytecode_segment_lengths(&self) -> &NestedIntList {
        &self.bytecode_segment_lengths
    }

    pub fn get_entry_point(
        &self,
        call: &CallEntryPoint,
    ) -> Result<EntryPointV1, PreExecutionError> {
        if call.entry_point_type == EntryPointType::Constructor
            && call.entry_point_selector != selector_from_name(CONSTRUCTOR_ENTRY_POINT_NAME)
        {
            return Err(PreExecutionError::InvalidConstructorEntryPointName);
        }

        let entry_points_of_same_type = &self.0.entry_points_by_type[&call.entry_point_type];
        let filtered_entry_points: Vec<_> = entry_points_of_same_type
            .iter()
            .filter(|ep| ep.selector == call.entry_point_selector)
            .collect();

        match &filtered_entry_points[..] {
            [] => Err(PreExecutionError::EntryPointNotFound(call.entry_point_selector)),
            [entry_point] => Ok((*entry_point).clone()),
            _ => Err(PreExecutionError::DuplicatedEntryPointSelector {
                selector: call.entry_point_selector,
                typ: call.entry_point_type,
            }),
        }
    }

    /// Returns the estimated VM resources required for computing Casm hash.
    /// This is an empiric measurement of several bytecode lengths, which constitutes as the
    /// dominant factor in it.
    fn estimate_casm_hash_computation_resources(&self) -> ExecutionResources {
        estimate_casm_hash_computation_resources(&self.bytecode_segment_lengths)
    }

    // Returns the set of segments that were visited according to the given visited PCs.
    // Each visited segment must have its starting PC visited, and is represented by it.
    fn get_visited_segments(
        &self,
        visited_pcs: &HashSet<usize>,
    ) -> Result<Vec<usize>, TransactionExecutionError> {
        let mut reversed_visited_pcs: Vec<_> = visited_pcs.iter().cloned().sorted().rev().collect();
        get_visited_segments(&self.bytecode_segment_lengths, &mut reversed_visited_pcs, &mut 0)
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<ContractClassV1, ProgramError> {
        let casm_contract_class: CasmContractClass = serde_json::from_str(raw_contract_class)?;
        let contract_class: ContractClassV1 = casm_contract_class.try_into()?;

        Ok(contract_class)
    }

    /// Returns an empty contract class for testing purposes.
    #[cfg(any(feature = "testing", test))]
    pub fn empty_for_testing() -> Self {
        Self(Arc::new(ContractClassV1Inner {
            program: Default::default(),
            entry_points_by_type: Default::default(),
            hints: Default::default(),
            bytecode_segment_lengths: NestedIntList::Leaf(0),
        }))
    }
}

/// Returns the estimated VM resources required for computing Casm hash (for Cairo 1 contracts).
///
/// Note: the function focuses on the bytecode size, and currently ignores the cost handling the
/// class entry points.
pub fn estimate_casm_hash_computation_resources(
    bytecode_segment_lengths: &NestedIntList,
) -> ExecutionResources {
    // The constants in this function were computed by running the Casm code on a few values
    // of `bytecode_segment_lengths`.
    match bytecode_segment_lengths {
        NestedIntList::Leaf(length) => {
            // The entire contract is a single segment (old Sierra contracts).
            &ExecutionResources {
                n_steps: 474,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([(POSEIDON_BUILTIN_NAME.to_string(), 10)]),
            } + &poseidon_hash_many_cost(*length)
        }
        NestedIntList::Node(segments) => {
            // The contract code is segmented by its functions.
            let mut execution_resources = ExecutionResources {
                n_steps: 491,
                n_memory_holes: 0,
                builtin_instance_counter: HashMap::from([(POSEIDON_BUILTIN_NAME.to_string(), 11)]),
            };
            let base_segment_cost = ExecutionResources {
                n_steps: 24,
                n_memory_holes: 1,
                builtin_instance_counter: HashMap::from([(POSEIDON_BUILTIN_NAME.to_string(), 1)]),
            };
            for segment in segments {
                let NestedIntList::Leaf(length) = segment else {
                    panic!(
                        "Estimating hash cost is only supported for segmentation depth at most 1."
                    );
                };
                execution_resources += &poseidon_hash_many_cost(*length);
                execution_resources += &base_segment_cost;
            }
            execution_resources
        }
    }
}

// Returns the set of segments that were visited according to the given visited PCs and segment
// lengths.
// Each visited segment must have its starting PC visited, and is represented by it.
// visited_pcs should be given in reversed order, and is consumed by the function.
fn get_visited_segments(
    segment_lengths: &NestedIntList,
    visited_pcs: &mut Vec<usize>,
    bytecode_offset: &mut usize,
) -> Result<Vec<usize>, TransactionExecutionError> {
    let mut res = Vec::new();

    match segment_lengths {
        NestedIntList::Leaf(length) => {
            let segment = *bytecode_offset..*bytecode_offset + length;
            if visited_pcs.last().is_some_and(|pc| segment.contains(pc)) {
                res.push(segment.start);
            }

            while visited_pcs.last().is_some_and(|pc| segment.contains(pc)) {
                visited_pcs.pop();
            }
            *bytecode_offset += length;
        }
        NestedIntList::Node(segments) => {
            for segment in segments {
                let segment_start = *bytecode_offset;
                let next_visited_pc = visited_pcs.last().copied();

                let visited_inner_segments =
                    get_visited_segments(segment, visited_pcs, bytecode_offset)?;

                if next_visited_pc.is_some_and(|pc| pc != segment_start)
                    && !visited_inner_segments.is_empty()
                {
                    return Err(TransactionExecutionError::InvalidSegmentStructure(
                        next_visited_pc.unwrap(),
                        segment_start,
                    ));
                }

                res.extend(visited_inner_segments);
            }
        }
    }
    Ok(res)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractClassV1Inner {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPointV1>>,
    pub hints: HashMap<String, Hint>,
    bytecode_segment_lengths: NestedIntList,
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct EntryPointV1 {
    pub selector: EntryPointSelector,
    pub offset: EntryPointOffset,
    pub builtins: Vec<String>,
}

impl EntryPointV1 {
    pub fn pc(&self) -> usize {
        self.offset.0
    }
}

// Implementation of the TryInto trait to convert a reference of ContractClassV1 into
// CasmContractClass.
impl TryInto<CasmContractClass> for &ContractClassV1 {
    // Definition of the error type that can be returned during the conversion.
    type Error = ProgramError;

    // Implementation of the try_into function which performs the conversion.
    fn try_into(self) -> Result<CasmContractClass, Self::Error> {
        // Converting the program data into a vector of BigUintAsHex.
        let bytecode: Vec<cairo_lang_utils::bigint::BigUintAsHex> = self
            .program
            .iter_data()
            .map(|x| cairo_lang_utils::bigint::BigUintAsHex {
                value: x.get_int_ref().unwrap().to_biguint(),
            })
            .collect();

        // Serialize the Program object to JSON bytes.
        let serialized_program = self.program.serialize()?;
        // Deserialize the JSON bytes into a serde_json::Value.
        let json_value: serde_json::Value = serde_json::from_slice(&serialized_program)?;

        // Extract the hints from the JSON value.
        let hints = json_value.get("hints").ok_or_else(|| {
            ProgramError::Parse(serde::ser::Error::custom("failed to parse hints"))
        })?;

        // Transform the hints into a vector of tuples (usize, Vec<Hint>).
        let hints: Vec<(usize, Vec<Hint>)> = hints
            .as_object() // Convert to JSON object.
            .unwrap()
            .iter()
            .map(|(key, value)| {
                // Transform each hint value into a Vec<Hint>.
                let hints: Vec<Hint> = value
                    .as_array() // Convert to JSON array.
                    .unwrap()
                    .iter()
                    .map(|hint_params| {
                        // Extract the "code" parameter and convert to a string.
                        let hint_param_code = hint_params.get("code").unwrap().clone();
                        let hint_string = hint_param_code.as_str().expect("failed to parse hint as string");

                        // Retrieve the hint from the self.hints map.
                        self.hints.get(hint_string).expect("failed to get hint").clone()
                    })
                    .collect();
                // Convert the key to usize and create a tuple (usize, Vec<Hint>).
                (key.parse().unwrap(), hints)
            })
            .collect();

        // Define the bytecode segment lengths
        let bytecode_segment_lengths = Some(self.bytecode_segment_lengths.clone());

        // Transform the entry points of type Constructor into CasmContractEntryPoint.
        let constructor = self
            .entry_points_by_type
            .get(&EntryPointType::Constructor)
            .unwrap_or(&vec![])
            .iter()
            .map(|constructor| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(constructor.selector.0.bytes()),
                offset: constructor.offset.0,
                builtins: constructor.builtins.clone(),
            })
            .collect();

        // Transform the entry points of type External into CasmContractEntryPoint.
        let external = self
            .entry_points_by_type
            .get(&EntryPointType::External)
            .unwrap_or(&vec![])
            .iter()
            .map(|external| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(external.selector.0.bytes()),
                offset: external.offset.0,
                builtins: external.builtins.clone(),
            })
            .collect();

        // Transform the entry points of type L1Handler into CasmContractEntryPoint.
        let l1_handler = self
            .entry_points_by_type
            .get(&EntryPointType::L1Handler)
            .unwrap_or(&vec![])
            .iter()
            .map(|l1_handler| CasmContractEntryPoint {
                selector: num_bigint::BigUint::from_bytes_be(l1_handler.selector.0.bytes()),
                offset: l1_handler.offset.0,
                builtins: l1_handler.builtins.clone(),
            })
            .collect();

        // Construct the CasmContractClass from the extracted and transformed data.
        Ok(CasmContractClass {
            prime: num_bigint::BigUint::from_str_radix(&self.program.prime()[2..], 16)
                .expect("failed to parse prime"),
            compiler_version: "".to_string(),
            bytecode,
            bytecode_segment_lengths,
            hints,
            pythonic_hints: None,
            entry_points_by_type:
                cairo_lang_starknet_classes::casm_contract_class::CasmContractEntryPoints {
                    constructor,
                    external,
                    l1_handler,
                },
        })
    }
}

impl TryFrom<CasmContractClass> for ContractClassV1 {
    type Error = ProgramError;

    fn try_from(class: CasmContractClass) -> Result<Self, Self::Error> {
        let data: Vec<MaybeRelocatable> = class
            .bytecode
            .into_iter()
            .map(|x| MaybeRelocatable::from(Felt252::from(x.value)))
            .collect();

        let mut hints: HashMap<usize, Vec<HintParams>> = HashMap::new();
        for (i, hint_list) in class.hints.iter() {
            let hint_params: Result<Vec<HintParams>, ProgramError> =
                hint_list.iter().map(hint_to_hint_params).collect();
            hints.insert(*i, hint_params?);
        }

        // Collect a sting to hint map so that the hint processor can fetch the correct [Hint]
        // for each instruction.
        let mut string_to_hint: HashMap<String, Hint> = HashMap::new();
        for (_, hint_list) in class.hints.iter() {
            for hint in hint_list.iter() {
                string_to_hint.insert(serde_json::to_string(hint)?, hint.clone());
            }
        }

        let builtins = vec![]; // The builtins are initialize later.
        let main = Some(0);
        let reference_manager = ReferenceManager { references: Vec::new() };
        let identifiers = HashMap::new();
        let error_message_attributes = vec![];
        let instruction_locations = None;

        let program = Program::new(
            builtins,
            data,
            main,
            hints,
            reference_manager,
            identifiers,
            error_message_attributes,
            instruction_locations,
        )?;

        let mut entry_points_by_type = HashMap::new();
        entry_points_by_type.insert(
            EntryPointType::Constructor,
            convert_entry_points_v1(class.entry_points_by_type.constructor)?,
        );
        entry_points_by_type.insert(
            EntryPointType::External,
            convert_entry_points_v1(class.entry_points_by_type.external)?,
        );
        entry_points_by_type.insert(
            EntryPointType::L1Handler,
            convert_entry_points_v1(class.entry_points_by_type.l1_handler)?,
        );

        let bytecode_segment_lengths = class
            .bytecode_segment_lengths
            .unwrap_or_else(|| NestedIntList::Leaf(program.data_len()));

        Ok(Self(Arc::new(ContractClassV1Inner {
            program,
            entry_points_by_type,
            hints: string_to_hint,
            bytecode_segment_lengths,
        })))
    }
}

// V0 utilities.

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {
    let deprecated_program = DeprecatedProgram::deserialize(deserializer)?;
    sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
}

/// Converts the program type from Cairo VM into a SN API-compatible type.
pub fn serialize_program<S: Serializer>(
    program: &Program,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let deprecated_program = cairo_vm_to_sn_api_program(program.clone())
        .map_err(|err| serde::ser::Error::custom(err.to_string()))?;
    deprecated_program.serialize(serializer)
}

// V1 utilities.

// TODO(spapini): Share with cairo-lang-runner.
fn hint_to_hint_params(hint: &cairo_lang_casm::hints::Hint) -> Result<HintParams, ProgramError> {
    Ok(HintParams {
        code: serde_json::to_string(hint)?,
        accessible_scopes: vec![],
        flow_tracking_data: FlowTrackingData {
            ap_tracking: ApTracking::new(),
            reference_ids: HashMap::new(),
        },
    })
}

fn convert_entry_points_v1(
    external: Vec<CasmContractEntryPoint>,
) -> Result<Vec<EntryPointV1>, ProgramError> {
    external
        .into_iter()
        .map(|ep| -> Result<_, ProgramError> {
            Ok(EntryPointV1 {
                selector: EntryPointSelector(felt_to_stark_felt(&Felt252::from(ep.selector))),
                offset: EntryPointOffset(ep.offset),
                builtins: ep.builtins.into_iter().map(|builtin| builtin + "_builtin").collect(),
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
// TODO(Ayelet,10/02/2024): Change to bytes.
pub struct ClassInfo {
    contract_class: ContractClass,
    sierra_program_length: usize,
    abi_length: usize,
}

impl ClassInfo {
    pub fn bytecode_length(&self) -> usize {
        self.contract_class.bytecode_length()
    }

    pub fn contract_class(&self) -> ContractClass {
        self.contract_class.clone()
    }

    pub fn sierra_program_length(&self) -> usize {
        self.sierra_program_length
    }

    pub fn abi_length(&self) -> usize {
        self.abi_length
    }

    pub fn code_size(&self) -> usize {
        (self.bytecode_length() + self.sierra_program_length())
            // We assume each felt is a word.
            * eth_gas_constants::WORD_WIDTH
            + self.abi_length()
    }

    pub fn new(
        contract_class: &ContractClass,
        sierra_program_length: usize,
        abi_length: usize,
    ) -> ContractClassResult<Self> {
        let (contract_class_version, condition) = match contract_class {
            ContractClass::V0(_) => (0, sierra_program_length == 0),
            ContractClass::V1(_) => (1, sierra_program_length > 0),
            ContractClass::V1Sierra(_) => (1, sierra_program_length > 0),
        };

        if condition {
            Ok(Self { contract_class: contract_class.clone(), sierra_program_length, abi_length })
        } else {
            Err(ContractClassError::ContractClassVersionSierraProgramLengthMismatch {
                contract_class_version,
                sierra_program_length,
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SierraContractClassV1(pub Arc<SierraContractClassV1Inner>);
impl Deref for SierraContractClassV1 {
    type Target = SierraContractClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SierraContractClassV1 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        let entrypoint = self.deref().entry_points_by_type.constructor.first()?;
        Some(contract_entrypoint_to_entrypoint_selector(entrypoint))
    }

    pub fn try_from_json_string(
        raw_contract_class: &str,
    ) -> Result<SierraContractClassV1, ProgramError> {
        let sierra_contract_class: SierraContractClass = serde_json::from_str(raw_contract_class)?;
        let contract_class: SierraContractClassV1 = sierra_contract_class.try_into()?;

        Ok(contract_class)
    }

    pub fn to_casm_contract_class(
        self,
    ) -> Result<CasmContractClass, StarknetSierraCompilationError> {
        let sierra_contract_class = SierraContractClass {
            // todo(rodro): can we do better than cloning?
            sierra_program: self.sierra_program_raw.clone(),
            entry_points_by_type: self.entry_points_by_type.clone(),
            abi: None,
            sierra_program_debug_info: None,
            contract_class_version: String::default(),
        };

        CasmContractClass::from_contract_class(sierra_contract_class, false, usize::MAX)
    }
}

impl TryFrom<SierraContractClass> for SierraContractClassV1 {
    // TODO error type
    type Error = ProgramError;

    fn try_from(class: SierraContractClass) -> Result<Self, Self::Error> {
        // todo(rodro): we are having two instances of a sierra program, one it's object form
        // and another in its felt encoded form. This can be avoided by either:
        //   1. Having access to the encoding/decoding functions
        //   2. Refactoring the code on the Cairo mono-repo
        Ok(Self(Arc::new(SierraContractClassV1Inner {
            sierra_program: class.extract_sierra_program().unwrap(),
            entry_points_by_type: class.entry_points_by_type,
            sierra_program_raw: class.sierra_program,
        })))
    }
}

impl Serialize for SierraContractClassV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the SierraContractClassV1 instance to CasmContractClass
        let casm_contract_class: CasmContractClass = self
            .clone()
            .to_casm_contract_class()
            .map_err(|err| serde::ser::Error::custom(err.to_string()))?;

        // Serialize the JSON string to bytes
        casm_contract_class.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SierraContractClassV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a JSON value
        let json_value: serde_json::Value = Deserialize::deserialize(deserializer)?;

        // Convert into a JSON string
        let json_string = serde_json::to_string(&json_value)
            .map_err(|err| DeserializationError::custom(err.to_string()))?;

        // Use try_from_json_string to deserialize into ContractClassV1
        SierraContractClassV1::try_from_json_string(&json_string)
            .map_err(|err| DeserializationError::custom(err.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SierraContractClassV1Inner {
    pub sierra_program: SierraProgram,
    pub entry_points_by_type: SierraContractEntryPoints,
    sierra_program_raw: Vec<BigUintAsHex>,
}
