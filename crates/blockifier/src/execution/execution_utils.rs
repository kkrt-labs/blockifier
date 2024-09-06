use std::collections::HashMap;
use std::str::FromStr;

use cairo_lang_runner::casm_run::format_next_item;
use cairo_vm::serde::deserialize_program::{
    deserialize_array_of_bigint_hex, Attribute, HintParams, Identifier, ReferenceManager,
};
use cairo_vm::types::builtin_name::BuiltinName;
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::{MaybeRelocatable, Relocatable};
use cairo_vm::vm::errors::memory_errors::MemoryError;
use cairo_vm::vm::errors::vm_errors::VirtualMachineError;
use cairo_vm::vm::runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources};
use cairo_vm::vm::vm_core::VirtualMachine;
use num_bigint::BigUint;
use starknet_api::core::ClassHash;
use starknet_api::deprecated_contract_class::Program as DeprecatedProgram;
use starknet_api::transaction::Calldata;
use starknet_types_core::felt::Felt;

use super::entry_point::ConstructorEntryPointExecutionResult;
use super::errors::ConstructorEntryPointExecutionError;
use crate::execution::call_info::{CallInfo, Retdata};
use crate::execution::contract_class::ContractClass;
use crate::execution::entry_point::{
    execute_constructor_entry_point, CallEntryPoint, ConstructorContext,
    EntryPointExecutionContext, EntryPointExecutionResult,
};
use crate::execution::errors::PostExecutionError;
use crate::execution::{deprecated_entry_point_execution, entry_point_execution};
use crate::state::errors::StateError;
use crate::state::state_api::State;
use crate::transaction::objects::TransactionInfo;

pub type Args = Vec<CairoArg>;

pub const SEGMENT_ARENA_BUILTIN_SIZE: usize = 3;

/// Executes a specific call to a contract entry point and returns its output.
pub fn execute_entry_point_call(
    call: CallEntryPoint,
    contract_class: ContractClass,
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
) -> EntryPointExecutionResult<CallInfo> {
    match contract_class {
        ContractClass::V0(contract_class) => {
            deprecated_entry_point_execution::execute_entry_point_call(
                call,
                contract_class,
                state,
                resources,
                context,
            )
        }
        ContractClass::V1(contract_class) => entry_point_execution::execute_entry_point_call(
            call,
            contract_class,
            state,
            resources,
            context,
        ),
    }
}

pub fn read_execution_retdata(
    runner: &CairoRunner,
    retdata_size: MaybeRelocatable,
    retdata_ptr: &MaybeRelocatable,
) -> Result<Retdata, PostExecutionError> {
    let retdata_size = match retdata_size {
        MaybeRelocatable::Int(retdata_size) => usize::try_from(retdata_size.to_bigint())
            .map_err(PostExecutionError::RetdataSizeTooBig)?,
        relocatable => {
            return Err(VirtualMachineError::ExpectedIntAtRange(Box::new(Some(relocatable))).into());
        }
    };

    Ok(Retdata(felt_range_from_ptr(&runner.vm, Relocatable::try_from(retdata_ptr)?, retdata_size)?))
}

pub fn felt_from_ptr(
    vm: &VirtualMachine,
    ptr: &mut Relocatable,
) -> Result<Felt, VirtualMachineError> {
    let felt = vm.get_integer(*ptr)?.into_owned();
    *ptr = (*ptr + 1)?;
    Ok(felt)
}

pub fn write_u256(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: BigUint,
) -> Result<(), MemoryError> {
    write_felt(vm, ptr, Felt::from(&value & BigUint::from(u128::MAX)))?;
    write_felt(vm, ptr, Felt::from(value >> 128))
}

pub fn felt_range_from_ptr(
    vm: &VirtualMachine,
    ptr: Relocatable,
    size: usize,
) -> Result<Vec<Felt>, VirtualMachineError> {
    let values = vm.get_integer_range(ptr, size)?;
    // Extract values as `Felt`.
    let values = values.into_iter().map(|felt| *felt).collect();
    Ok(values)
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReferenceTmp {
    pub ap_tracking_data: cairo_vm::serde::deserialize_program::ApTracking,
    pub pc: Option<usize>,
    pub value_address: cairo_vm::serde::deserialize_program::ValueAddress,
}

// TODO(Elin,01/05/2023): aim to use LC's implementation once it's in a separate crate.
pub fn sn_api_to_cairo_vm_program(program: DeprecatedProgram) -> Result<Program, ProgramError> {
    let identifiers = serde_json::from_value::<HashMap<String, Identifier>>(program.identifiers)?;
    let builtins = serde_json::from_value(program.builtins)?;
    let data = deserialize_array_of_bigint_hex(program.data)?;
    let hints = serde_json::from_value::<HashMap<usize, Vec<HintParams>>>(program.hints)?;
    let main = None;
    let error_message_attributes = match program.attributes {
        serde_json::Value::Null => vec![],
        attributes => serde_json::from_value::<Vec<Attribute>>(attributes)?
            .into_iter()
            .filter(|attr| attr.name == "error_message")
            .collect(),
    };

    let instruction_locations = None;

    // Deserialize the references in ReferenceManager
    let mut reference_manager = ReferenceManager::default();

    if let Some(references_value) = program.reference_manager.get("references") {
        for reference_value in references_value
            .as_array()
            .unwrap_or_else(|| panic!("Expected 'references' to be an array"))
        {
            if reference_value.get("value_address").is_some() {
                // Directly deserialize references_value without using deserialize_value_address
                let tmp = serde_json::from_value::<ReferenceTmp>(reference_value.clone())?;

                reference_manager.references.push(
                    cairo_vm::serde::deserialize_program::Reference {
                        ap_tracking_data: tmp.ap_tracking_data,
                        pc: tmp.pc,
                        value_address: tmp.value_address,
                    },
                );
            } else {
                let tmp = serde_json::from_value::<cairo_vm::serde::deserialize_program::Reference>(
                    reference_value.clone(),
                )?;

                reference_manager.references.push(tmp);
            }
        }
    }

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

    Ok(program)
}

// Function to convert MaybeRelocatable to hex string
fn maybe_relocatable_to_hex_string(mr: &MaybeRelocatable) -> String {
    match mr {
        MaybeRelocatable::Int(value) => value.to_hex_string(),
        _ => unimplemented!(),
    }
}

// Helper function to process identifiers
fn process_identifiers(
    json_value: &serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    json_value.get("identifiers").and_then(serde_json::Value::as_object).map_or_else(
        serde_json::Map::new,
        |identifiers_obj| {
            identifiers_obj
                .iter()
                .filter_map(|(key, inner_value)| {
                    inner_value.as_object().map(|inner_obj| {
                        let filtered_inner_obj = inner_obj
                            .iter()
                            .filter_map(|(inner_key, inner_val)| {
                                if inner_val.is_null() {
                                    return None;
                                }

                                // Rename the key if it's "type_" to "type"
                                let renamed_key = if inner_key == "type_" {
                                    "type".to_string()
                                } else {
                                    inner_key.to_string()
                                };

                                // Check if the key is "value" and extract the "val" field to
                                // convert it to a JSON number
                                let value = match renamed_key.as_str() {
                                    "value" => serde_json::Value::Number(
                                        serde_json::Number::from_str(
                                            &Felt::from_str(inner_val.as_str().unwrap())
                                                .unwrap()
                                                .to_string(),
                                        )
                                        .unwrap(),
                                    ),
                                    _ => inner_val.clone(),
                                };

                                Some((renamed_key, value))
                            })
                            .collect::<serde_json::Map<_, _>>();

                        (key.to_string(), serde_json::Value::Object(filtered_inner_obj))
                    })
                })
                .collect()
        },
    )
}

// Main function to convert Program to DeprecatedProgram
pub fn cairo_vm_to_sn_api_program(program: Program) -> Result<DeprecatedProgram, ProgramError> {
    // Serialize the Program object to JSON bytes
    let serialized_program = program.serialize()?;
    // Deserialize the JSON bytes into a Value
    let json_value: serde_json::Value = serde_json::from_slice(&serialized_program)?;

    // Convert the data segment to the expected hex string format
    let data = serde_json::to_value(
        program
            .iter_data()
            .cloned()
            .map(|mr: MaybeRelocatable| maybe_relocatable_to_hex_string(&mr))
            .collect::<Vec<String>>(),
    )?;

    // Process identifiers
    let identifiers = process_identifiers(&json_value);

    // println!("identifiers: {:?}", identifiers);

    Ok(DeprecatedProgram {
        attributes: json_value.get("attributes").cloned().unwrap_or_default(),
        builtins: json_value.get("builtins").cloned().unwrap(),
        compiler_version: json_value.get("compiler_version").cloned().unwrap_or_default(),
        data,
        debug_info: json_value.get("debug_info").cloned().unwrap_or_default(),
        hints: json_value.get("hints").cloned().unwrap(),
        identifiers: serde_json::Value::Object(identifiers),
        main_scope: json_value.get("main_scope").cloned().unwrap_or_default(),
        prime: json_value.get("prime").cloned().unwrap(),
        reference_manager: json_value.get("reference_manager").cloned().unwrap(),
    })
}

#[derive(Debug)]
// Invariant: read-only.
pub struct ReadOnlySegment {
    pub start_ptr: Relocatable,
    pub length: usize,
}

/// Represents read-only segments dynamically allocated during execution.
#[derive(Debug, Default)]
// Invariant: read-only.
pub struct ReadOnlySegments(Vec<ReadOnlySegment>);

impl ReadOnlySegments {
    pub fn allocate(
        &mut self,
        vm: &mut VirtualMachine,
        data: &Vec<MaybeRelocatable>,
    ) -> Result<Relocatable, MemoryError> {
        let start_ptr = vm.add_memory_segment();
        self.0.push(ReadOnlySegment { start_ptr, length: data.len() });
        vm.load_data(start_ptr, data)?;
        Ok(start_ptr)
    }

    pub fn validate(&self, vm: &VirtualMachine) -> Result<(), PostExecutionError> {
        for segment in &self.0 {
            let used_size = vm
                .get_segment_used_size(
                    segment
                        .start_ptr
                        .segment_index
                        .try_into()
                        .expect("The size of isize and usize should be the same."),
                )
                .expect("Segments must contain the allocated read-only segment.");
            if segment.length != used_size {
                return Err(PostExecutionError::SecurityValidationError(
                    "Read-only segments".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn mark_as_accessed(&self, runner: &mut CairoRunner) -> Result<(), PostExecutionError> {
        for segment in &self.0 {
            runner.vm.mark_address_range_as_accessed(segment.start_ptr, segment.length)?;
        }

        Ok(())
    }
}

/// Instantiates the given class and assigns it an address.
/// Returns the call info of the deployed class' constructor execution.
pub fn execute_deployment(
    state: &mut dyn State,
    resources: &mut ExecutionResources,
    context: &mut EntryPointExecutionContext,
    ctor_context: ConstructorContext,
    constructor_calldata: Calldata,
    remaining_gas: u64,
) -> ConstructorEntryPointExecutionResult<CallInfo> {
    // Address allocation in the state is done before calling the constructor, so that it is
    // visible from it.
    let deployed_contract_address = ctor_context.storage_address;
    let current_class_hash =
        state.get_class_hash_at(deployed_contract_address).map_err(|error| {
            ConstructorEntryPointExecutionError::new(error.into(), &ctor_context, None)
        })?;
    if current_class_hash != ClassHash::default() {
        return Err(ConstructorEntryPointExecutionError::new(
            StateError::UnavailableContractAddress(deployed_contract_address).into(),
            &ctor_context,
            None,
        ));
    }

    state.set_class_hash_at(deployed_contract_address, ctor_context.class_hash).map_err(
        |error| ConstructorEntryPointExecutionError::new(error.into(), &ctor_context, None),
    )?;

    execute_constructor_entry_point(
        state,
        resources,
        context,
        ctor_context,
        constructor_calldata,
        remaining_gas,
    )
}

pub fn write_felt(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    felt: Felt,
) -> Result<(), MemoryError> {
    write_maybe_relocatable(vm, ptr, felt)
}

pub fn write_maybe_relocatable<T: Into<MaybeRelocatable>>(
    vm: &mut VirtualMachine,
    ptr: &mut Relocatable,
    value: T,
) -> Result<(), MemoryError> {
    vm.insert_value(*ptr, value)?;
    *ptr = (*ptr + 1)?;
    Ok(())
}

pub fn max_fee_for_execution_info(tx_info: &TransactionInfo) -> Felt {
    match tx_info {
        TransactionInfo::Current(_) => 0,
        TransactionInfo::Deprecated(tx_info) => tx_info.max_fee.0,
    }
    .into()
}

pub fn format_panic_data(felts: &[Felt]) -> String {
    let mut felts = felts.iter().copied();
    let mut items = Vec::new();
    while let Some(item) = format_next_item(&mut felts) {
        items.push(item.quote_if_string());
    }
    if let [item] = &items[..] { item.clone() } else { format!("({})", items.join(", ")) }
}

/// Returns the VM resources required for running `poseidon_hash_many` in the Starknet OS.
pub fn poseidon_hash_many_cost(data_length: usize) -> ExecutionResources {
    ExecutionResources {
        n_steps: (data_length / 10) * 55
            + ((data_length % 10) / 2) * 18
            + (data_length % 2) * 3
            + 21,
        n_memory_holes: 0,
        builtin_instance_counter: HashMap::from([(BuiltinName::poseidon, data_length / 2 + 1)]),
    }
}
