from impacket.dpapi import DPAPI_BLOB

hex_data = (
    # "e4560100"
    # "020001bb"
    # "4c010000"

    # Version
    "01000000"
    # GuidCredential
    "d08c9ddf0115d1118c7a00c04fc297eb"
    # MasterKeyVersion
    "01000000"
    # GuidMasterKey
    "ce4b48a6199fe14ca7a32e7a0e0b6b59"
    # Flags
    "04000000"

    # Description
    "40000000"
    "5400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e000000"

    # CryptAlgo
    "10660000"
    # CryptAlgoLen
    "00010000"

    # Salt
    "20000000"
    "d777c210c1bc73d287fb57995316390e39eb6ad043cd0819e082a6cb148b3847"

    # HMacKeyLen
    "00000000"
    # HMacKey

    # HashAlgo
    "0e800000"
    # HashAlgoLen
    "00020000"

    # HMac
    "20000000"
    "e92d13481be68b22b5b37ab39a654b3e73f66aa7af474931a64c4784bdc432f9"

    # Data
    "30000000"
    "1567c9fc6879ba11cc3efb3082be3ab71c18f9cdef080ddc1ab91779179b7942731ab82d8e31b68a0fb1cb3b0c83158e"

    # Sign
    "40000000"
    "eeb830224374f315cf0c60c9c740326f7ee799f221751158d271593366eda7a34366125be111732aa359831e83665088f42c6fc8f75e933d07c997fc05f9309c"

    # контрольная сумма
    # "b6a06bf1a4188acf"


    # "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e66e08836590e048"
    # "adc7635ec505d3cd040000004000000054006800690073002000690073002000"
    # "74006800650020006400650073006300720069007000740069006f006e002000"
    # "73007400720069006e0067002e00000010660000000100002000000082237ac4"
    # "c2ed87b105088f7f0c371c9e0a3b7698348b2936ec2564f1ea5b63ad00000000"
    # "0e80000000020000200000001e7f858920fb2f1476a78888c662b81d2aa2dc25"
    # "17dab6069bba4faadb6b9ba2300000001a01548cbf2a2ce7068826d60d424dd5"
    # "aaa5c1c210d4c7eca123e4ea2e803c4c56a8a9e61a9f67aa3449303004b76e42"
    # "40000000b0415015ce04b87912f2e3a2b774eca180225311da4c9e9a8370484d"
    # "f3a41cc4a21627d8d88edce6a40513f1e877a81e79a2edec29cc6a7edb02657e"
    # "fdeb7ee125a573f9fe8797c9"
)
blob_bytes = bytes.fromhex(hex_data)

# impacket.dpapi.Structure.debug = 1

# Создаем объект DPAPI_BLOB из байтов
blob = DPAPI_BLOB(blob_bytes)

# Теперь мы можем обращаться к его полям
print("--- Анализ структуры DPAPI BLOB ---")

# binascii.hexlify(blob['Salt']).decode()

print(f"Version          : {blob['Version']}")
print(f"GuidCredential   : {blob['GuidCredential'].hex()}")
print(f"MasterKeyVersion : {blob['MasterKeyVersion']}")
print(f"GuidMasterKey    : {blob['GuidMasterKey'].hex()}")
print(f"Flags            : {blob['Flags']}")
print()
print(f"DescriptionLen   : {blob['DescriptionLen']}")
print(f"Description      : ({len(blob['Description'])}) {blob['Description'].decode('utf-16-le').strip()}")
print(f"Description      : ({len(blob['Description'])}) {blob['Description'].hex()}")
print()
print(f"CryptAlgoLen     : {blob['CryptAlgoLen']}")
print(f"CryptAlgo        : {blob['CryptAlgo']} (AES-256)")
print()
print(f"SaltLen          : {blob['SaltLen']}")
print(f"Salt             : ({len(blob['Salt'])}) {blob['Salt'].hex()}")
print()
print(f"HMacKeyLen       : {blob['HMacKeyLen']}")
print(f"HMacKey          : ({len(blob['HMacKey'])}) {blob['HMacKey'].hex()}")
print()
print(f"HashAlgo         : {blob['HashAlgo']} (SHA-512)")
print(f"HashAlgoLen      : {blob['HashAlgoLen']}")
print()
print(f"HMac             : {blob['HMac'].hex()}")
print()
print(f"DataLen          : {blob['DataLen']}")
print(f"Data             : ({len(blob['Data'])}) {blob['Data'].hex()}")
print()
print(f"SignLen          : {blob['SignLen']}")
print(f"Sign             : ({len(blob['Sign'])}) {blob['Sign'].hex()}")


# Для расшифровки с помощью impacket потребуется сам Мастер-ключ в расшифрованном виде.
# Это сложный процесс, который выходит за рамки простого парсинга.
# Например:
# if master_key:
#     decrypted_data = blob.decrypt(master_key)
#     print("\nРасшифрованные данные:", decrypted_data)
