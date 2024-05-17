use pretty_assertions::assert_eq;
use starknet_api::hash::StarkFelt;
use starknet_api::state::StorageKey;
use starknet_api::transaction::Calldata;
use starknet_api::{calldata, stark_felt};
use test_case::test_case;

use crate::abi::abi_utils::selector_from_name;
use crate::context::ChainInfo;
use crate::execution::call_info::{CallExecution, Retdata};
use crate::execution::entry_point::CallEntryPoint;
use crate::execution::syscalls::syscall_tests::REQUIRED_GAS_STORAGE_READ_WRITE_TEST;
use crate::retdata;
use crate::state::state_api::StateReader;
use crate::test_utils::contracts::FeatureContract;
use crate::test_utils::initial_test_state::test_state;
use crate::test_utils::{trivial_external_entry_point_new, CairoVersion, BALANCE};

#[test_case(FeatureContract::TestContract(CairoVersion::Cairo1), REQUIRED_GAS_STORAGE_READ_WRITE_TEST; "VM")]
fn test_storage_read_write(test_contract: FeatureContract, expected_gas: u64) {
    let chain_info = &ChainInfo::create_for_testing();
    let mut state = test_state(chain_info, BALANCE, &[(test_contract, 1)]);

    let key = stark_felt!(1234_u16);
    let value = stark_felt!(18_u8);
    let calldata = calldata![key, value];
    let entry_point_call = CallEntryPoint {
        calldata,
        entry_point_selector: selector_from_name("test_storage_read_write"),
        ..trivial_external_entry_point_new(test_contract)
    };
    let storage_address = entry_point_call.storage_address;
    assert_eq!(
        entry_point_call.execute_directly(&mut state).unwrap().execution,
        CallExecution {
            retdata: retdata![stark_felt!(value)],
            gas_consumed: expected_gas,
            ..CallExecution::default()
        }
    );

    // Verify that the state has changed.
    let value_from_state =
        state.get_storage_at(storage_address, StorageKey::try_from(key).unwrap()).unwrap();
    assert_eq!(value_from_state, value);
}
