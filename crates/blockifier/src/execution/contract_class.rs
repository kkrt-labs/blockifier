use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use cairo_felt::Felt252;
use cairo_lang_casm;
use cairo_lang_casm::hints::Hint;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_vm::serde::deserialize_program::{
    ApTracking, FlowTrackingData, HintParams, ReferenceManager,
};
use cairo_vm::types::errors::program_errors::ProgramError;
use cairo_vm::types::program::Program;
use cairo_vm::types::relocatable::MaybeRelocatable;
use cairo_vm::vm::runners::builtin_runner::{HASH_BUILTIN_NAME, POSEIDON_BUILTIN_NAME};
use cairo_vm::vm::runners::cairo_runner::ExecutionResources as VmExecutionResources;
use serde::de::Error as DeserializationError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_api::core::EntryPointSelector;
use starknet_api::deprecated_contract_class::{
    ContractClass as DeprecatedContractClass, EntryPoint, EntryPointOffset, EntryPointType,
    Program as DeprecatedProgram,
};

use crate::abi::abi_utils::selector_from_name;
use crate::abi::constants::{self, CONSTRUCTOR_ENTRY_POINT_NAME};
use crate::execution::errors::PreExecutionError;
use crate::execution::execution_utils::{felt_to_stark_felt, sn_api_to_cairo_vm_program};

use super::execution_utils::cairo_vm_to_sn_api_program;

/// Represents a runnable StarkNet contract class (meaning, the program is runnable by the VM).
/// We wrap the actual class in an Arc to avoid cloning the program when cloning the class.
// Note: when deserializing from a SN API class JSON string, the ABI field is ignored
// by serde, since it is not required for execution.
#[derive(Clone, Debug, Eq, PartialEq, derive_more::From, Serialize, Deserialize)]
pub enum ContractClass {
    V0(ContractClassV0),
    V1(ContractClassV1),
}

impl ContractClass {
    pub fn constructor_selector(&self) -> Option<EntryPointSelector> {
        match self {
            ContractClass::V0(class) => class.constructor_selector(),
            ContractClass::V1(class) => class.constructor_selector(),
        }
    }

    pub fn estimate_casm_hash_computation_resources(&self) -> VmExecutionResources {
        match self {
            ContractClass::V0(class) => class.estimate_casm_hash_computation_resources(),
            ContractClass::V1(class) => class.estimate_casm_hash_computation_resources(),
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

    fn estimate_casm_hash_computation_resources(&self) -> VmExecutionResources {
        let hashed_data_size = (constants::CAIRO0_ENTRY_POINT_STRUCT_SIZE * self.n_entry_points())
            + self.n_builtins()
            + self.bytecode_length()
            + 1; // Hinted class hash.
        // The hashed data size is approximately the number of hashes (invoked in hash chains).
        let n_steps = constants::N_STEPS_PER_PEDERSEN * hashed_data_size;

        VmExecutionResources {
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

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV0Inner {
    // #[serde(serialize_with = "serialize_program", deserialize_with = "deserialize_program")]
    #[serde(deserialize_with = "deserialize_program")]
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
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV1(pub Arc<ContractClassV1Inner>);
impl Deref for ContractClassV1 {
    type Target = ContractClassV1Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ContractClassV1 {
    fn constructor_selector(&self) -> Option<EntryPointSelector> {
        Some(self.0.entry_points_by_type[&EntryPointType::Constructor].first()?.selector)
    }

    pub fn bytecode_length(&self) -> usize {
        self.program.data_len()
    }

    pub fn get_entry_point(
        &self,
        call: &super::entry_point::CallEntryPoint,
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
    fn estimate_casm_hash_computation_resources(&self) -> VmExecutionResources {
        let bytecode_length = self.bytecode_length() as f64;
        let n_steps = (503.0 + bytecode_length * 5.7) as usize;
        let n_poseidon_builtins = (10.9 + bytecode_length * 0.5) as usize;

        VmExecutionResources {
            n_steps,
            n_memory_holes: 0,
            builtin_instance_counter: HashMap::from([(
                POSEIDON_BUILTIN_NAME.to_string(),
                n_poseidon_builtins,
            )]),
        }
    }

    pub fn try_from_json_string(raw_contract_class: &str) -> Result<ContractClassV1, ProgramError> {
        let casm_contract_class: CasmContractClass = serde_json::from_str(raw_contract_class)?;
        let contract_class: ContractClassV1 = casm_contract_class.try_into()?;

        Ok(contract_class)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractClassV1Inner {
    pub program: Program,
    pub entry_points_by_type: HashMap<EntryPointType, Vec<EntryPointV1>>,
    pub hints: HashMap<String, Hint>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
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

        Ok(Self(Arc::new(ContractClassV1Inner {
            program,
            entry_points_by_type,
            hints: string_to_hint,
        })))
    }
}

// V0 utilities.

/// Converts the program type Cairo VM-compatible type to SN API.
pub fn serialize_program<S>(
    program: &Program,
    serializer: S
)
-> Result<S::Ok, S::Error>
where S: Serializer
{

    let program = cairo_vm_to_sn_api_program(program).expect("failed to convert cairo-vm program to sn-api program");
    program.serialize(serializer)
}

/// Converts the program type from SN API into a Cairo VM-compatible type.
pub fn deserialize_program<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Program, D::Error> {


    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum TmpProgram {
        CairoVM(Program),
        SNProgram(DeprecatedProgram)
    }

    let program: TmpProgram = TmpProgram::deserialize(deserializer)?;

    match program {
       TmpProgram::CairoVM(program) => {
            Ok(program)
       }
       TmpProgram::SNProgram(deprecated_program) => {
        sn_api_to_cairo_vm_program(deprecated_program)
        .map_err(|err| DeserializationError::custom(err.to_string()))
       }
    }
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
                selector: EntryPointSelector(felt_to_stark_felt(
                    &Felt252::try_from(ep.selector).unwrap(),
                )),
                offset: EntryPointOffset(ep.offset),
                builtins: ep.builtins.into_iter().map(|builtin| builtin + "_builtin").collect(),
            })
        })
        .collect()
}


#[cfg(test)]
mod test {
    use std::{sync::Arc, fs,
        // collections::HashMap, fs
    };

    use cairo_vm::{types::program::Program,
        // serde::deserialize_program::{HintParams, FlowTrackingData, ApTracking}
    };
    use serde::{Serialize, Deserialize};

    use crate::execution::contract_class::{ContractClassV1Inner, ContractClassV0, ContractClass};

    use super::ContractClassV0Inner;

    #[test]
    fn test_serialization_inner_class_v0() {
        let class_inner = ContractClassV0Inner::default();
        let class_inner = Arc::new(class_inner);
        let class_inner = ContractClassV0(class_inner);
        let value = serde_json::to_string_pretty(&class_inner).unwrap();
        println!("value is -----> {}", value)
    }

    #[test]
    fn test_serialization_contract_class() {
        let class_inner = ContractClassV0Inner::default();
        let class_inner = Arc::new(class_inner);
        let class_inner = ContractClassV0(class_inner);

        let contract_class = ContractClass::V0(class_inner);
        let value = serde_json::to_string_pretty(&contract_class).unwrap();
        println!("value is -----> {}", value)
    }

    #[test]
    fn test_serialization_inner_class_v1() {
        let class_inner = ContractClassV1Inner::default();
        let value = serde_json::to_string_pretty(&class_inner).unwrap();
        println!("value is -----> {}", value)
    }

    //TODO(harsh): delete this
    #[test]
    fn test_deserialization_of_contract_class_v_0() {
       #[derive(Serialize, Deserialize, Debug)]
       #[serde(untagged)]
       enum Tmp{
        A(Program)
       }

//        let mut hints : HashMap<usize, Vec<HintParams>>= HashMap::new();
//        let mut hint: HintParams = HintParams { code: String::from("some random code"), accessible_scopes: vec![String::from("abc")],
//        flow_tracking_data: FlowTrackingData {
//         ap_tracking: ApTracking{
//             group: 0,
//             offset: 5
//         } ,
//         reference_ids: HashMap::new()
//        }}
//        ;

//        let _ = hint.flow_tracking_data.reference_ids.insert(String::from("some_Key"), 42);
//        hints.insert(20,vec![hint]);

//        let hints_str = serde_json::to_string_pretty(&hints).unwrap();

//        fs::write("./somerand.json", &hints_str).unwrap();
//        println!("pertty string is  {:?}", hints_str);

//     let hints_str = r#"
//     {
//         "20": [
//           {
//             "code": "n -= 1\nids.continue_copying = 1 if n > 0 else 0",
//             "accessible_scopes": [
//               "starkware.cairo.common.memcpy",
//               "starkware.cairo.common.memcpy.memcpy"
//             ],
//             "flow_tracking_data": {
//               "ap_tracking": {
//                 "group": 2,
//                 "offset": 5
//               },
//               "reference_ids": {
//                 "starkware.cairo.common.memcpy.memcpy.continue_copying": 1
//               }
//             }
//           }
//         ]
//       }
//    "#;

//        let _: HashMap<usize, Vec<HintParams>> = serde_json::from_str(&hints_str).unwrap();

//     //    println!("val----> {}",val);

//        let b = Program::default();
//        let _ = serde_json::to_string_pretty(&b).unwrap();

       let val = r#"{
        "shared_program_data": {
          "data": [
            {
              "Int": {
                "value": {
                  "val": [
                    2147450879,
                    67600385
                  ]
                }
              }
            }
          ],
          "hints": {
            "20": [
              {
                "code": "n -= 1\nids.continue_copying = 1 if n > 0 else 0",
                "accessible_scopes": [
                  "starkware.cairo.common.memcpy",
                  "starkware.cairo.common.memcpy.memcpy"
                ],
                "flow_tracking_data": {
                  "ap_tracking": {
                    "group": 2,
                    "offset": 5
                  },
                  "reference_ids": {
                    "starkware.cairo.common.memcpy.memcpy.continue_copying": 1
                  }
                }
              }
            ]
          },
          "main": null,
          "start": null,
          "end": null,
          "error_message_attributes": [],
          "instruction_locations": null,
          "identifiers": {
            "__main__.ContractDeployed": {
              "pc": null,
              "type_": "namespace",
              "value": null,
              "full_name": null,
              "members": null,
              "cairo_type": null
            }
          },
          "reference_manager": []
        },
        "constants": {},
        "builtins": []
      }
      "#;

      let program: Program = serde_json::from_str(&val).unwrap();

      let str = serde_json::to_string_pretty(&program).unwrap();
      fs::write("./tmp.json", &str).unwrap();
      let  _ : Program = serde_json::from_str(&val).unwrap();


        // let mut ds = serde_json::Deserializer::from_str(&val);
        // let _: Tmp = serde_path_to_error::deserialize(&mut ds).unwrap();

    //     println!("c ---> {:?}", c);
}

}
