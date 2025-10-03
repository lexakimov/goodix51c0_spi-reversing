import hashlib
import uuid

from impacket.dpapi import DPAPI_BLOB

hex_data = (
    # "e4560100"
    # "020001bb"
    # "4c010000"

    # Содержимое Goodix_Cache.bin:
    "01000000d08c9ddf0115d1118c7a00c04fc297eb010000004c9ce67c50c6"
    "b04bb637cd1c725114ee0400000040000000540068006900730020006900"
    "730020007400680065002000640065007300630072006900700074006900"
    "6f006e00200073007400720069006e0067002e0000001066000000010000"
    "200000006e4fa0f0c6eb2c205bf30919735f8e39ce6a751a66e135de92fd"
    "aa1c9f16df43000000000e8000000002000020000000be119bea5888c588"
    "612186d6e3326314be59647949eb5552b8d6c9c5ad0d981130000000cb4a"
    "b34e61d04580cacc208521685be96bbba73559878d70df9f85738ab57436"
    "d506a8d012f893387fe332fe3253f9bc400000005aa42ac11c54b4e8af8a"
    "bc02e1cf9ebda823bd056513e6c5dc7de5a0baa3c5e357da67a34bd335f1"
    "5429c6c449a3c45b3792f827d392e5f72a001530c0817a3a6be5a0cbeef0"
    "3c0b"
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
print()
print()

print("--- Извлекаем seed ---")
if len(blob_bytes) < 332:
    raise ValueError("DPAPI blob too short to contain seed bytes")
seed = blob_bytes[324:332]
# seed = os.urandom(8)
print(f"Seed             : {seed.hex()}")
print()

print("--- Генерим root key из констант (заданы в коде драйвера) ---")
CONST_1 = bytes.fromhex("9d 79 92 b3 84 02 b6 6c 81 d1 f5 55 21 89 42 a9")
CONST_2 = bytes.fromhex("18 48 d7 15 50 d2 70 d2 19 c8 06 32 ab 4f 8b b3")
CONST_3 = bytes.fromhex("e4 7c 89 38 db 52 50 f0 20 56 17 ee 17 da 4e b4")

root_key_buffer = bytearray(16)

for i in range(8):
    root_key_buffer[i] = CONST_1[i] ^ CONST_2[i] ^ CONST_1[i + 8]

for i in range(8, 16):
    root_key_buffer[i] = CONST_2[i] ^ CONST_3[i] ^ CONST_3[i - 8]

root_key = bytes(root_key_buffer)
print(f"Root key        : {root_key.hex()}")
print()

print("--- Генерим entropy для DPAPI ---")
# entropy
seed_hash = hashlib.sha256(seed).digest()
entropy_material = seed_hash[:16] + root_key
entropy_hash = hashlib.sha256(entropy_material).digest()
entropy = seed_hash[16:] + entropy_hash  # 16 + 32 = 48 байт
print(f"DPAPI entropy   : {entropy.hex()}")
print()

expected_hash = bytes.fromhex("8d8e99805d1e2289c541125d5add5dd530894cc8500d035541b8c0a5961ec05d")
psk_wb = bytes.fromhex(
    "fad1e5b87930265db0ed2544e3615056f619fc11e6a558f8e0d92003e479ff41"
    "02ff200000007ddcfcdba9e81b0c4815638d0305303b562e5f4014f40b9d76ed"
    "f2755d9e5dbd8694b0508df786193deddfca4854fef93f68a5d5cfdeec152429"
    "0576fdad0c67"
)
sha256_hash = hashlib.sha256()
sha256_hash.update(psk_wb)
actual_hash = sha256_hash.digest()

print(f"Expected PSK WB hash : {expected_hash.hex()}")
print(f"  Actual PSK WB hash : {actual_hash.hex()}")
print("hash are equal" if expected_hash == actual_hash else "hash are different")
print()

# Расшифровать PSK на Windows можно через mimikatz указав энтропию (под тем же пользователем):
# dpapi::blob /in:"C:\ProgramData\Goodix\Goodix_Cache.bin" /entropy:633b9d417af094e9b570069f30cd42ee0d050aa6e65127f7907c1087319821ccde810722cd73529701e9b6160dd6ee1c /unprotect

# Для расшифровки с помощью impacket потребуется сам Мастер-ключ в расшифрованном виде.
# master_key = bytes.fromhex("0000")
# decrypted_data = blob.decrypt(key=master_key, entropy=entropy)
# print("\nРасшифрованные данные:", decrypted_data.hex())
