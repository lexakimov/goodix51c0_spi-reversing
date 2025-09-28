import hashlib
import os
import uuid

from impacket.dpapi import DPAPI_BLOB

hex_data = (
    # "e4560100"
    # "020001bb"
    # "4c010000"

    "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e66e08836590"
    "e048adc7635ec505d3cd0400000040000000540068006900730020006900"
    "730020007400680065002000640065007300630072006900700074006900"
    "6f006e00200073007400720069006e0067002e0000001066000000010000"
    "2000000082237ac4c2ed87b105088f7f0c371c9e0a3b7698348b2936ec25"
    "64f1ea5b63ad000000000e80000000020000200000001e7f858920fb2f14"
    "76a78888c662b81d2aa2dc2517dab6069bba4faadb6b9ba2300000001a01"
    "548cbf2a2ce7068826d60d424dd5aaa5c1c210d4c7eca123e4ea2e803c4c"
    "56a8a9e61a9f67aa3449303004b76e4240000000b0415015ce04b87912f2"
    "e3a2b774eca180225311da4c9e9a8370484df3a41cc4a21627d8d88edce6"
    "a40513f1e877a81e79a2edec29cc6a7edb02657efdeb7ee125a573f9fe87"
    "97c9"
)
blob_bytes = bytes.fromhex(hex_data)

# impacket.dpapi.Structure.debug = 1

blob = DPAPI_BLOB(blob_bytes)

print("--- Анализ структуры DPAPI BLOB ---")
print(f"Version          : {blob['Version']}")
print(f"GuidCredential   : {uuid.UUID(bytes_le=blob['GuidCredential'])}")
print(f"MasterKeyVersion : {blob['MasterKeyVersion']}")
print(f"GuidMasterKey    : {uuid.UUID(bytes_le=blob['GuidMasterKey'])}")
print(f"Flags            : {blob['Flags']}")
print()
print(f"DescriptionLen   : {blob['DescriptionLen']}")
print(f"Description      : ({len(blob['Description'])}) {blob['Description'].decode('utf-16-le').strip()}")
print(f"Description      : ({len(blob['Description'])}) {blob['Description'].hex()}")
print()
print(f"CryptAlgo        : {blob['CryptAlgo']} (AES-256)")
print(f"CryptAlgoLen     : {blob['CryptAlgoLen']}")
print()
print(f"SaltLen          : {blob['SaltLen']}")
print(f"Salt             : ({len(blob['Salt'])}) {blob['Salt'].hex()}")
print()
print(f"HMacKeyLen       : {blob['HMacKeyLen']}")
print(f"HmackKey         : ({len(blob['HMacKey'])}) {blob['HMacKey'].hex()}")
print()
print(f"HashAlgo         : {blob['HashAlgo']} (SHA-512)")
print(f"HashAlgoLen      : {blob['HashAlgoLen']}")
print()
print(f"Hmac2KeyLen      : {blob['_HMac']}")
print(f"Hmack2Key        : ({len(blob['HMac'])}) {blob['HMac'].hex()}")
print()
print(f"DataLen          : {blob['DataLen']}")
print(f"Data             : ({len(blob['Data'])}) {blob['Data'].hex()}")
print()
print(f"SignLen          : {blob['SignLen']}")
print(f"Sign             : ({len(blob['Sign'])}) {blob['Sign'].hex()}")

print("-------------------------------------------------------")

if len(blob_bytes) < 332:
    raise ValueError("DPAPI blob too short to contain seed bytes")
seed_from_cache = blob_bytes[324:332]
print(f"Seed             : {seed_from_cache.hex()}")
print()
print()

CONST_A = bytes.fromhex("84170400881b040004b24d00881b0400")
CONST_B = bytes.fromhex("a4210400e8b24d00a421040043220400")
CONST_C = bytes.fromhex("18af4d0044220400b22604003cb34d00")


def _derive_root_key() -> bytes:
    root = bytearray(16)
    for i in range(8):
        root[i] = CONST_A[i] ^ CONST_B[i] ^ CONST_A[i + 8]
    for i in range(8, 16):
        root[i] = CONST_B[i] ^ CONST_C[i] ^ CONST_C[i - 8]
    return bytes(root)


ROOT_KEY = _derive_root_key()


def generate_random_bytes(count: int) -> bytes:
    return os.urandom(count)


def build_dpapi_entropy(seed_: bytes | None) -> tuple[bytes, bytes]:
    if not seed_ or len(seed_) != 8 or seed_ == b"\x00" * 8:
        seed_ = generate_random_bytes(8)
    seed_hash = hashlib.sha256(seed_).digest()
    entropy_material = seed_hash[:16] + ROOT_KEY
    entropy_hash = hashlib.sha256(entropy_material).digest()
    entropy_ = seed_hash[16:] + entropy_hash  # 16 + 32 = 48 байт
    return entropy_, seed_



entropy, seed = build_dpapi_entropy(seed_from_cache)

print(f"Root key        : {ROOT_KEY.hex()}")
print(f"Seed (in use)   : {seed.hex()}")
print(f"DPAPI entropy   : {entropy.hex()}")

# Для расшифровки с помощью impacket потребуется сам Мастер-ключ в расшифрованном виде.
# master_key = bytes.fromhex("0000")
# decrypted_data = blob.decrypt(key=master_key, entropy=entropy)
# print("\nРасшифрованные данные:", decrypted_data.hex())
