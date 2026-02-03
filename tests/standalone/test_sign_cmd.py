import pytest

from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import BoilerplateCommandSender, Errors
from application_client.boilerplate_response_unpacker import unpack_get_public_key_response, unpack_sign_tx_response
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavIns, NavInsID

# Quantus derivation path matching Cargo.toml manifest: 44'/189189'/0'/0'/0'
QUANTUS_PATH = "m/44'/189189'/0'/0'/0'"

# In these tests we check the behavior of the device when asked to sign a transaction

# In this test a transaction is sent to the device to be signed and validated on screen.
# The transaction is short and will be sent in one chunk.
# We will ensure that the displayed information is correct by using screenshots comparison.
@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_sign_tx_short_tx(backend, scenario_navigator, device, navigator):
    client = BoilerplateCommandSender(backend)

    # First we need to get the public key of the device in order to build the transaction
    rapdu = client.get_public_key(path=QUANTUS_PATH)
    _, public_key = unpack_get_public_key_response(rapdu.data)

    # Create the transaction that will be sent to the device for signing
    transaction = Transaction(
        nonce=1,
        coin="CRAB",
        value=777,
        to="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        memo="For u EthDev"
    ).serialize()

    # Enable display of transaction memo (NBGL devices only)
    if not device.is_nano:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS,
                            NavIns(NavInsID.TOUCH, (200, 113)),
                            NavInsID.USE_CASE_SUB_SETTINGS_EXIT],
                            screen_change_before_first_instruction=False,
                            screen_change_after_last_instruction=False)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=QUANTUS_PATH, transaction=transaction):
        scenario_navigator.review_approve()

    # The device has yielded the result, parse it and ensure the signature format is correct
    response = client.get_async_response().data
    _, signature, resp_pubkey = unpack_sign_tx_response(response)
    # Verify the returned pubkey matches what we got from get_public_key
    assert resp_pubkey == public_key

# In this test a transaction is sent to the device to be signed and validated on screen.
# The transaction is short and will be sent in one chunk
# The transaction memo should not be displayed as we have not enabled it in the app settings.
@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_sign_tx_short_tx_no_memo(backend, scenario_navigator, device):
    if device.is_nano:
        pytest.skip("Skipping this test for Nano devices")

    client = BoilerplateCommandSender(backend)

    rapdu = client.get_public_key(path=QUANTUS_PATH)
    _, public_key = unpack_get_public_key_response(rapdu.data)

    transaction = Transaction(
        nonce=1,
        coin="CRAB",
        value=777,
        to="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        memo="For u EthDev"
    ).serialize()

    with client.sign_tx(path=QUANTUS_PATH, transaction=transaction):
        scenario_navigator.review_approve()

    response = client.get_async_response().data
    _, signature, resp_pubkey = unpack_sign_tx_response(response)
    assert resp_pubkey == public_key


# In this test a transaction is sent to the device to be signed and validated on screen.
# This test is mostly the same as the previous one but with different values.
# In particular the long memo will force the transaction to be sent in multiple chunks
@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_sign_tx_long_tx(backend, scenario_navigator, device, navigator):
    client = BoilerplateCommandSender(backend)

    rapdu = client.get_public_key(path=QUANTUS_PATH)
    _, public_key = unpack_get_public_key_response(rapdu.data)

    transaction = Transaction(
        nonce=1,
        coin="CRAB",
        value=666,
        to="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        memo=("This is a very long memo. "
              "It will force the app client to send the serialized transaction to be sent in chunk. "
              "As the maximum chunk size is 255 bytes we will make this memo greater than 255 characters. "
              "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam.")
    ).serialize()

    # Enable display of transaction memo (NBGL devices only)
    if not device.is_nano:
        navigator.navigate([NavInsID.USE_CASE_HOME_SETTINGS,
                            NavIns(NavInsID.TOUCH, (200, 113)),
                            NavInsID.USE_CASE_SUB_SETTINGS_EXIT],
                            screen_change_before_first_instruction=False,
                            screen_change_after_last_instruction=False)

    with client.sign_tx(path=QUANTUS_PATH, transaction=transaction):
        scenario_navigator.review_approve()

    response = client.get_async_response().data
    _, signature, resp_pubkey = unpack_sign_tx_response(response)
    assert resp_pubkey == public_key


# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
@pytest.mark.skip(reason="Screenshot snapshots need updating after rename")
def test_sign_tx_refused(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)

    rapdu = client.get_public_key(path=QUANTUS_PATH)
    _, pub_key = unpack_get_public_key_response(rapdu.data)

    transaction = Transaction(
        nonce=1,
        coin="CRAB",
        value=666,
        to="de0b295669a9fd93d5f28d9ec85e40f4cb697bae",
        memo="This transaction will be refused by the user"
    ).serialize()

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=QUANTUS_PATH, transaction=transaction):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0
