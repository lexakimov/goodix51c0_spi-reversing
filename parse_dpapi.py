from impacket.dpapi import DPAPI_BLOB

# impacket.dpapi.Structure.debug = 1

hex_data = (
    # "e4560100"
    # "020001bb"
    # "4c010000"

    "01000000d08c9ddf0115d1118c7a00c04fc297eb01000000ce4b48a6199f"
    "e14ca7a32e7a0e0b6b590400000040000000540068006900730020006900"
    "730020007400680065002000640065007300630072006900700074006900"
    "6f006e00200073007400720069006e0067002e0000001066000000010000"
    "20000000d777c210c1bc73d287fb57995316390e39eb6ad043cd0819e082"
    "a6cb148b3847000000000e8000000002000020000000e92d13481be68b22"
    "b5b37ab39a654b3e73f66aa7af474931a64c4784bdc432f9300000001567"
    "c9fc6879ba11cc3efb3082be3ab71c18f9cdef080ddc1ab91779179b7942"
    "731ab82d8e31b68a0fb1cb3b0c83158e40000000eeb830224374f315cf0c"
    "60c9c740326f7ee799f221751158d271593366eda7a34366125be111732a"
    "a359831e83665088f42c6fc8f75e933d07c997fc05f9309cb6a06bf1a418"
    "8acf"

)
blob_bytes = bytes.fromhex(hex_data)

# Создаем объект DPAPI_BLOB из байтов
blob = DPAPI_BLOB(blob_bytes)

# Теперь мы можем обращаться к его полям
print("--- Анализ структуры DPAPI BLOB ---")

# print(f"IV:               {binascii.hexlify(blob['iv']).decode()}")
# binascii.hexlify(blob['Salt']).decode()

print(f"Flags            : {blob['Flags']}")
print(f"Version          : {blob['Version']}")
print(f"MasterKeyVersion : {blob['MasterKeyVersion']}")
print(f"GuidCredential   : {blob['GuidCredential'].hex()}")
print(f"GuidMasterKey    : {blob['GuidMasterKey'].hex()}")
print()
print(f"Description      : ({len(blob['Description'])}) {blob['Description'].decode('utf-16-le').strip()}")
print(f"DescriptionLen   : {blob['DescriptionLen']}")
print()
print(f"CryptAlgo        : {blob['CryptAlgo']} (AES-256)")
print(f"CryptAlgoLen     : {blob['CryptAlgoLen']}")
print()
print(f"HashAlgo         : {blob['HashAlgo']} (SHA-512)")
print(f"HashAlgoLen      : {blob['HashAlgoLen']}")
print()
print(f"Salt             : ({len(blob['Salt'])}) {blob['Salt'].hex()}")
print(f"SaltLen          : {blob['SaltLen']}")
print()
print(f"Data             : ({len(blob['Data'])}) {blob['Data'].hex()}")
print(f"DataLen          : {blob['DataLen']}")
print()
print(f"Sign             : ({len(blob['Sign'])}) {blob['Sign'].hex()}")
print(f"SignLen          : {blob['SignLen']}")
print()
print(f"HMac             : {blob['HMac'].hex()}")
print()
print(f"HMacKey          : ({len(blob['HMacKey'])}) {blob['HMacKey'].hex()}")
print(f"HMacKeyLen       : {blob['HMacKeyLen']}")


# Для расшифровки с помощью impacket потребуется сам Мастер-ключ в расшифрованном виде.
# Это сложный процесс, который выходит за рамки простого парсинга.
# Например:
# if master_key:
#     decrypted_data = blob.decrypt(master_key)
#     print("\nРасшифрованные данные:", decrypted_data)