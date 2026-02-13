import pytest

from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, DILITHIUM_PUBLICKEYBYTES
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns

# Quantus derivation path matching Cargo.toml manifest: 44'/189189'/0'/0'/0'
QUANTUS_PATH = "m/44'/189189'/0'/0'/0'"


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
# and returns a valid Dilithium (ML-DSA-87) public key
def test_get_public_key_no_confirm(backend):
    client = BoilerplateCommandSender(backend)
    response = client.get_public_key(path=QUANTUS_PATH).data
    pub_key_len, public_key = unpack_get_public_key_response(response)

    assert pub_key_len == DILITHIUM_PUBLICKEYBYTES
    assert len(public_key) == DILITHIUM_PUBLICKEYBYTES

    # Verify determinism: same path produces same key
    response2 = client.get_public_key(path=QUANTUS_PATH).data
    _, public_key2 = unpack_get_public_key_response(response2)
    assert public_key == public_key2


@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_get_public_key_confirm_accepted(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)

    with client.get_public_key_with_confirmation(path=QUANTUS_PATH):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    pub_key_len, public_key = unpack_get_public_key_response(response)

    assert pub_key_len == DILITHIUM_PUBLICKEYBYTES
    assert len(public_key) == DILITHIUM_PUBLICKEYBYTES


@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=QUANTUS_PATH):
            scenario_navigator.address_review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
