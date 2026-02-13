from typing import Tuple
from struct import unpack

# remainder, data_len, data
def pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
    return buffer[size:], buffer[0:size]

# remainder, data_len, data
def pop_size_prefixed_buf_from_buf(buffer:bytes) -> Tuple[bytes, int, bytes]:
    data_len = buffer[0]
    return buffer[1+data_len:], data_len, buffer[1:data_len+1]

# Unpack from response:
# response = app_name (var)
def unpack_get_app_name_response(response: bytes) -> str:
    return response.decode("ascii")

# Unpack from response:
# response = MAJOR (1)
#            MINOR (1)
#            PATCH (1)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int]:
    assert len(response) == 3
    major, minor, patch = unpack("BBB", response)
    return (major, minor, patch)

# Unpack from response:
# response = format_id (1)
#            app_name_raw_len (1)
#            app_name_raw (var)
#            version_raw_len (1)
#            version_raw (var)
#            unused_len (1)
#            unused (var)
def unpack_get_app_and_version_response(response: bytes) -> Tuple[str, str]:
    response, _ = pop_sized_buf_from_buffer(response, 1)
    response, _, app_name_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, version_raw = pop_size_prefixed_buf_from_buf(response)
    response, _, _ = pop_size_prefixed_buf_from_buf(response)

    assert len(response) == 0

    return app_name_raw.decode("ascii"), version_raw.decode("ascii")

# ML-DSA-87 (Dilithium) sizes
DILITHIUM_PUBLICKEYBYTES = 2592
DILITHIUM_SIGNBYTES = 4627

# Unpack from response:
# response = pub_key_len (2 bytes, big-endian u16)
#            pub_key (2592 bytes for ML-DSA-87)
def unpack_get_public_key_response(response: bytes) -> Tuple[int, bytes]:
    pub_key_len = int.from_bytes(response[0:2], byteorder='big')
    pub_key = response[2:2 + pub_key_len]

    assert pub_key_len == DILITHIUM_PUBLICKEYBYTES
    assert len(pub_key) == pub_key_len
    assert len(response) == 2 + pub_key_len
    return pub_key_len, pub_key

# Unpack from response:
# response = sig_len (4 bytes, big-endian u32)
#            signature (4627 bytes for ML-DSA-87)
#            pub_key (2592 bytes for ML-DSA-87)
def unpack_sign_tx_response(response: bytes) -> Tuple[int, bytes, bytes]:
    sig_len = int.from_bytes(response[0:4], byteorder='big')
    signature = response[4:4 + sig_len]
    pub_key = response[4 + sig_len:]

    assert sig_len == DILITHIUM_SIGNBYTES
    assert len(signature) == sig_len
    assert len(pub_key) == DILITHIUM_PUBLICKEYBYTES
    return sig_len, signature, pub_key
