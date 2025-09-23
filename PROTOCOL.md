```
OPTIONAL ━━━ reset device...
OPTIONAL if reset device или через timeout ━━━ get evk version
OPTIONAL ━━━ get mcu state
OPTIONAL ━━━ write 0xbb010002 && 0xbb010003
OPTIONAL ━━━ read 0xbb010002 (host psk hash)
OPTIONAL ━━━ read 0xbb020003 (psk mcu hash / pmk)
OPTIONAL ━━━ reset sensor
OPTIONAL ━━━ get MILAN_CHIPID
OPTIONAL ━━━ get OTP
OPTIONAL ━━━ reset sensor
OPTIONAL ━━━ setmode: idle
OPTIONAL ━━━ send Dac 0x380bb500b300b300
REQUIRED ━━━ upload mcu config
━━━ get image
```

> TODO разобраться в разнице пакетов TLS

> COMMAND_TLS_SUCCESSFULLY_ESTABLISHED


## Типы пакетов

- `A0` - Normal, plaintext packet.
- `B0` - Used during TLS handshake
- `B2` - Used when sending TLS encrypted image data

## Коды команд

- `0x0` NOP
    - `0x01` - init
- `0x2` Ima
    - `0x20` - setmode image
- `0x3` FDT(dow/up/man)
    - `0x36` - fdt manual
- `0x4` FF
- `0x5`
    - `0x50` - nav
- `0x6` Sle
- `0x7`
    - `0x70` - set mode: idle
- `0x8` REG
    - `0x82` - reg read write
- `0x9` CHIP
    - `0x90` - upload MCU config
    - `0x98` - send DAC
- `0xA` OTHER
    - `0xA6` - get OTP
    - `0xA8` - get evk version
- `0xB` MSG
    - `0xB0` - ACK
- `0xC` NOTI
- `0xD` TLSCONN
    - `0xD1` - get TLS handshake
    - `0xD5` - unlock TLS
- `0xE` PROD
    - `0xE0` - write specific data_type
    - `0xE4` - read specific data_type
- `0xF` UPFW

## Стандартный flow с описанием передаваемых сообщений

### Unlock TLS

init (для этой команды не обязателен)
```
write
    a0 08 00 a8
        a0    - флаг MSG_PROTOCOL
        0800  - полная длина следующего пакета в LE-notation
        a8    - контрольная сумма
    
    01 05 00 00 00 00 00 88
        01    - cmd
        0500  - длина последующего с контрольной суммой сообщения в LE-notation
        00000000 - payload
        88    - null checksum

not to wait for ack
```

Разблокировка TLS
```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма
    
    d5 03 00 00 00 d3
        d5    - cmd (tls ?)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        d3    - контрольная сумма

not to wait for ack
```

### Get Evk Version

init (обязателен)
```
write
    a0 08 00 a8
        a0    - флаг MSG_PROTOCOL
        0800  - полная длина следующего пакета в LE-notation
        a8    - контрольная сумма

    01 05 00 00 00 00 00 88
        01    - cmd
        0500  - длина последующего с контрольной суммой сообщения в LE-notation
        00000000 - payload
        88    - null checksum

not to wait for ack
```

Получение версии прошивки
```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма
    
    a8 03 00 00 00 ff
        a8    - cmd FIRMWARE_VERSION
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0000  - payload
        ff    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма
    
    b0 03 00 a8 07 48
        b0      - cmd ACK
        0300    - длина последующего с контрольной суммой сообщения в LE-notation
        a8      - cmd (далее)
        07      - cfg flag 0x7
        48      - контрольная сумма

read
    a0 1a 00 ba
        a0    - флаг MSG_PROTOCOL
        1a00  - полная длина следующего пакета в LE-notation (26)
        ba    - контрольная сумма
    
    a8 17 00 47 46 5f 48 43 34 36 30 53 45 43 5f 41 50 50 5f 31 34 32 31 30 00 68
    [                                   26                                      ]
        a8    - cmd FIRMWARE_VERSION
        1700  - длина последующего с контрольной суммой сообщения в LE-notation (23)
        4730  - GF_HC460SEC_APP_14210
        00    - пустой символ
        68    - контрольная сумма
```

### Get MCU config

init
```
write
    a0 08 00 a8
        a0    - флаг MSG_PROTOCOL
        0800  - полная длина следующего пакета в LE-notation
        a8    - контрольная сумма
    
    01 05 00 00 00 00 00 88
        01    - cmd
        0500  - длина последующего с контрольной суммой сообщения в LE-notation
        00000000 - payload
        88    - null checksum

not to wait for ack
```

???
```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    97 03 00 01 01 0f
        97    - cmd (UPLOAD_MCU_CONFIG(?))
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0101  - payload
        0f    - контрольная сумма

not to wait for ack

```

Получение флагов конфигурации MCU (см. [MCU_CONFIG.md](MCU_CONFIG.md))
```
write
    a0 09 00 a9
        a0    - флаг MSG_PROTOCOL
        0900  - полная длина следующего пакета в LE-notation
        a9    - контрольная сумма

    af 06 00 55 6b a3 00 00 93
        af    - cmd (get MCU config)
        0600  - длина последующего с контрольной суммой сообщения в LE-notation
        55
        6ba3  - TIMESTAMP
        0000  - payload
        93    - контрольная сумма

not to wait for ack

read
    a0 1a 00 ba
        a0    - флаг MSG_PROTOCOL
        1a00  - полная длина следующего пакета в LE-notation (26)
        ba    - контрольная сумма

    ae 17 00 04 00 30 00 00 00 00 01 60 00 00 00 00 01 00 00 04 25 02 00 00 00 24
        ae    - cmd (MCU_CONFIG)
        1700  - длина последующего с контрольной суммой сообщения в LE-notation
        0403000000000016000000000010000042502000000
        24    - контрольная сумма

```

### Get Evk Version (повтор)
+ init (так же как раньше)

Полагаю что на случай если после первой проверки пришлось обновить прошивку

---

### Проверка PSK

1.get host hash (host_psk_data)

.get seal data - смотрим наличие файла `Goodix_Cache.bin` (332 байта).

Если файл `Goodix_Cache.bin` пуст, то выполняем [read specific data_type 0xbb010002](#read-specific-data_type-0xbb010002)
Если файл `Goodix_Cache.bin` не пуст, то переходим сразу к [read specific data_type 0xbb020003](#read-specific-data_type-0xbb020003)

### read specific data_type 0xbb010002

`e4 0xbb010002` - прочитать host_psk_hash

```
write
    a0 0c 00 ac
        a0    - флаг MSG_PROTOCOL
        0c00  - полная длина следующего пакета в LE-notation
        ac    - контрольная сумма

    e4 09 00 02 00 01 bb 00 00 00 00 ff
        e4    - cmd (PRESET_PSK_READ)
        0900  - длина последующего с контрольной суммой сообщения в LE-notation
        020001bb - data_type в LE-notation (0xbb010002)
        0000  - нули
        ff    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма
    
    b0 03 00 e4 07 0c
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        e4    - cmd (PRESET_PSK_READ далее)
        07    - cfg flag 0x7
        0c    - контрольная сумма

------
read (вариант 1 - PSK найден, в ответе его хеш)
    a0 59 01 fa
        a0    - флаг MSG_PROTOCOL
        5901  - полная длина следующего пакета в LE-notation (345)
        a6    - контрольная сумма

    e4 56 01 00 02 00 01 bb 4c 01 00 00 01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb
    01 00 00 00 ce 4b 48 a6 19 9f e1 4c a7 a3 2e 7a 0e 0b 6b 59 04 00 00 00 40 00 00 00 54 00 68 00
    69 00 73 00 20 00 69 00 73 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00
    70 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00
    00 01 00 00 20 00 00 00 d7 77 c2 10 c1 bc 73 d2 87 fb 57 99 53 16 39 0e 39 eb 6a d0 43 cd 08 19
    e0 82 a6 cb 14 8b 38 47 00 00 00 00 0e 80 00 00 00 02 00 00 20 00 00 00 e9 2d 13 48 1b e6 8b 22
    b5 b3 7a b3 9a 65 4b 3e 73 f6 6a a7 af 47 49 31 a6 4c 47 84 bd c4 32 f9 30 00 00 00 15 67 c9 fc
    68 79 ba 11 cc 3e fb 30 82 be 3a b7 1c 18 f9 cd ef 08 0d dc 1a b9 17 79 17 9b 79 42 73 1a b8 2d
    8e 31 b6 8a 0f b1 cb 3b 0c 83 15 8e 40 00 00 00 ee b8 30 22 43 74 f3 15 cf 0c 60 c9 c7 40 32 6f
    7e e7 99 f2 21 75 11 58 d2 71 59 33 66 ed a7 a3 43 66 12 5b e1 11 73 2a a3 59 83 1e 83 66 50 88
    f4 2c 6f c8 f7 5e 93 3d 07 c9 97 fc 05 f9 30 9c b6 a0 6b f1 a4 18 8a cf 3b

        e4    - cmd (PRESET_PSK_READ READ)
        5601  - длина последующего с контрольной суммой сообщения в LE-notation (342)
        00
        02 00 01 bb [specific data_type 0xbb010002 (был указан в запросе)]
        4c 01 00 00 [длина host_psk_data (332)]
        
        [далее host_psk_data (содержимое Goodix_Cache.bin), длина 332]
        01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb
        01 00 00 00 ce 4b 48 a6 19 9f e1 4c a7 a3 2e 7a 0e 0b 6b 59 04 00 00 00 40 00 00 00 54 00 68 00
        69 00 73 00 20 00 69 00 73 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00
        70 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00
        00 01 00 00 20 00 00 00 d7 77 c2 10 c1 bc 73 d2 87 fb 57 99 53 16 39 0e 39 eb 6a d0 43 cd 08 19
        e0 82 a6 cb 14 8b 38 47 00 00 00 00 0e 80 00 00 00 02 00 00 20 00 00 00 e9 2d 13 48 1b e6 8b 22
        b5 b3 7a b3 9a 65 4b 3e 73 f6 6a a7 af 47 49 31 a6 4c 47 84 bd c4 32 f9 30 00 00 00 15 67 c9 fc
        68 79 ba 11 cc 3e fb 30 82 be 3a b7 1c 18 f9 cd ef 08 0d dc 1a b9 17 79 17 9b 79 42 73 1a b8 2d
        8e 31 b6 8a 0f b1 cb 3b 0c 83 15 8e 40 00 00 00 ee b8 30 22 43 74 f3 15 cf 0c 60 c9 c7 40 32 6f
        7e e7 99 f2 21 75 11 58 d2 71 59 33 66 ed a7 a3 43 66 12 5b e1 11 73 2a a3 59 83 1e 83 66 50 88
        f4 2c 6f c8 f7 5e 93 3d 07 c9 97 fc 05 f9 30 9c b6 a0 6b f1 a4 18 8a cf
        3b    - контрольная сумма

------
read (вариант 2 - неудача: PSK не найден)
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    e4 03 00 01 51 71
        e4    - cmd (PRESET_PSK_READ)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0151  - payload
        71    - контрольная сумма
```

Если (вариант 1 - PSK найден) - записываем host_psk_data (332 байта) в файл Goodix_Cache.bin

При неудаче (вариант 2 - PSK не найден) проверка повторяется еше раз.
Если после повтора опять неудача - выполняем [Generate, encrypt and write PSK to MCU](#generate-encrypt-and-write-psk-to-mcu)

### Generate, encrypt and write PSK to MCU

```
генерим PSK (32 байта):
    random not exist or invalid, generate new data
    CryptAcquireContext succeeded
    Random sequence generated: 8
    generate rootkey
    0.generate random psk
    CryptAcquireContext succeeded
    Random sequence generated: 32

шифруем его (на выходе 324 байта):
    1.seal psk
    inbuf_len 32, entropy_len 48, len_out 2048
    The encryption phase worked, 32, 324
    seal psk, ret 0x0 length before 32, length after:324

шифруем его (???) (на выходе 102 байта):
    2.process encrypted psk
    process ret 0x0 type 0xbb010003, length before 32, length after:102

пишем его в сканнер:
    3.write to mcu
    data_to_mcu_len 450 bytes, remainder4 is 2 bytes
    remainder4 is not 0, add 2 bytes then finally data_to_mcu_len 452 bytes
    write data: length 452, type 0xbb010002
    Entry, length 452
    Will Clear the cache buffer.
```

Двойная команда
`e0 0xbb010002 ... 0xbb010003` - записать host_psk_data (содержимое Goodix_Cache.bin) + зашифрованный psk

```
write
    a0 c8 01 69
        a0    - флаг MSG_PROTOCOL
        c801  - полная длина следующего пакета в LE-notation (456)
        69    - контрольная сумма
        
    e0 c5 01 02 00 01 bb 4c 01 00 00 01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb 01
    00 00 00 4c 9c e6 7c 50 c6 b0 4b b6 37 cd 1c 72 51 14 ee 04 00 00 00 40 00 00 00 54 00 68 00 69
    00 73 00 20 00 69 00 73 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70
    00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00 00
    01 00 00 20 00 00 00 6e 4f a0 f0 c6 eb 2c 20 5b f3 09 19 73 5f 8e 39 ce 6a 75 1a 66 e1 35 de 92
    fd aa 1c 9f 16 df 43 00 00 00 00 0e 80 00 00 00 02 00 00 20 00 00 00 be 11 9b ea 58 88 c5 88 61
    21 86 d6 e3 32 63 14 be 59 64 79 49 eb 55 52 b8 d6 c9 c5 ad 0d 98 11 30 00 00 00 cb 4a b3 4e 61
    d0 45 80 ca cc 20 85 21 68 5b e9 6b bb a7 35 59 87 8d 70 df 9f 85 73 8a b5 74 36 d5 06 a8 d0 12
    f8 93 38 7f e3 32 fe 32 53 f9 bc 40 00 00 00 5a a4 2a c1 1c 54 b4 e8 af 8a bc 02 e1 cf 9e bd a8
    23 bd 05 65 13 e6 c5 dc 7d e5 a0 ba a3 c5 e3 57 da 67 a3 4b d3 35 f1 54 29 c6 c4 49 a3 c4 5b 37
    92 f8 27 d3 92 e5 f7 2a 00 15 30 c0 81 7a 3a 6b e5 a0 cb ee f0 3c 0b 03 00 01 bb 66 00 00 00 fa
    d1 e5 b8 79 30 26 5d b0 ed 25 44 e3 61 50 56 f6 19 fc 11 e6 a5 58 f8 e0 d9 20 03 e4 79 ff 41 02
    ff 20 00 00 00 7d dc fc db a9 e8 1b 0c 48 15 63 8d 03 05 30 3b 56 2e 5f 40 14 f4 0b 9d 76 ed f2
    75 5d 9e 5d bd 86 94 b0 50 8d f7 86 19 3d ed df ca 48 54 fe f9 3f 68 a5 d5 cf de ec 15 24 29 05
    76 fd ad 0c 67 00 00 ad

              e0    - cmd PRESET_PSK_WRITE
            c501    - длина последующего с контрольной суммой сообщения в LE-notation (453)
        020001bb    - data_type в LE-notation [specific data_type 0xbb010002 (был указан в запросе)]
        4c010000    - длина последующего блока 0xbb010002 (332)

        [далее host_psk_data (содержимое Goodix_Cache.bin), длина 332]
        01 00 00 00 d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb 01 
        00 00 00 4c 9c e6 7c 50 c6 b0 4b b6 37 cd 1c 72 51 14 ee 04 00 00 00 40 00 00 00 54 00 68 00 69 
        00 73 00 20 00 69 00 73 00 20 00 74 00 68 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70 
        00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00 00 
        01 00 00 20 00 00 00 6e 4f a0 f0 c6 eb 2c 20 5b f3 09 19 73 5f 8e 39 ce 6a 75 1a 66 e1 35 de 92 
        fd aa 1c 9f 16 df 43 00 00 00 00 0e 80 00 00 00 02 00 00 20 00 00 00 be 11 9b ea 58 88 c5 88 61 
        21 86 d6 e3 32 63 14 be 59 64 79 49 eb 55 52 b8 d6 c9 c5 ad 0d 98 11 30 00 00 00 cb 4a b3 4e 61 
        d0 45 80 ca cc 20 85 21 68 5b e9 6b bb a7 35 59 87 8d 70 df 9f 85 73 8a b5 74 36 d5 06 a8 d0 12 
        f8 93 38 7f e3 32 fe 32 53 f9 bc 40 00 00 00 5a a4 2a c1 1c 54 b4 e8 af 8a bc 02 e1 cf 9e bd a8 
        23 bd 05 65 13 e6 c5 dc 7d e5 a0 ba a3 c5 e3 57 da 67 a3 4b d3 35 f1 54 29 c6 c4 49 a3 c4 5b 37 
        92 f8 27 d3 92 e5 f7 2a 00 15 30 c0 81 7a 3a 6b e5 a0 cb ee f0 3c 0b
        
        030001bb    - data_type в LE-notation [specific data_type 0xbb010003 (был указан в запросе)]
        66000000    - длина последующего блока 0xbb010003 (102)

        [далее зашифрованный psk (до - 32, после шифрования - 102 байта]
        fa
        d1 e5 b8 79 30 26 5d b0 ed 25 44 e3 61 50 56 f6 19 fc 11 e6 a5 58 f8 e0 d9 20 03 e4 79 ff 41 02
        ff 20 00 00 00 7d dc fc db a9 e8 1b 0c 48 15 63 8d 03 05 30 3b 56 2e 5f 40 14 f4 0b 9d 76 ed f2
        75 5d 9e 5d bd 86 94 b0 50 8d f7 86 19 3d ed df ca 48 54 fe f9 3f 68 a5 d5 cf de ec 15 24 29 05
        76 fd ad 0c 67
            0000    - remainder4 is not 0, add 2 bytes
              ad    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма
    
    b0 03 00 e0 07 10
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        e0    - cmd (PRESET_PSK_WRITE)
        07    - cfg flag 0x7
        0c    - контрольная сумма

read
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    e0 03 00 00 51 76
        e0    - cmd
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0051  - payload
        76    - контрольная сумма
```

После этого пишем host_psk_data (332 байта) в файл Goodix_Cache.bin

### read specific data_type 0xbb020003

```
расшифровываем 324 -> 32
  generate rootkey
  inbuf_len 324, entropy_len 48, len_out 32
  The decryption phase worked, 324, 32
  unseal return 0x0 length before 324, length after:32

преобразуем PSK в WB (32 -> 102)
  .wb data 
  wb return 0x0 length before 32, length after:102

хешируем WB (102 -> 32)
  .hash
  hash return 0x0 length before 102, length after:32
  ret 0x0, psk len 32, hash len 32, seal len 332, data from file flag 1 
```

`e4 0xbb020003` - прочитать mcu hash

```
write
    a0 0c 00 ac
        a0    - флаг MSG_PROTOCOL
        0c00  - полная длина следующего пакета в LE-notation
        ac    - контрольная сумма

    e4 09 00 03 00 02 bb 00 00 00 00 fd
        e4    - cmd (PRESET_PSK_READ)
        0900  - длина последующего с контрольной суммой сообщения в LE-notation
        030002bb - data_type в LE-notation
        0000  - нули
        ff    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 e4 07 0c
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        e4    - cmd (PRESET_PSK_READ далее)
        07    - cfg flag 0x7
        0c    - контрольная сумма

read
    a0 2d 00 cd
        a0    - флаг MSG_PROTOCOL
        2d00  - полная длина следующего пакета в LE-notation (45)
        cd    - контрольная сумма

    e4 2a 00 00 03 00 02 bb 20 00 00 00 8d 8e 99 80 5d 1e 22 89 c5 41 12 5d 5a dd 5d d5 30 89 4c c8 50 0d 03 55 41 b8 c0 a5 96 1e c0 5d d3
        e4    - cmd (PRESET_PSK_READ)
        2a00  - длина последующего с контрольной суммой сообщения в LE-notation (42)

        [далее payload + контролльная сумма = длина 42]:
        00 [далее остается 41 байт]
        030002bb    - data_type в LE-notation
        20 00 00 00 - длина в LE-notation (32)

        далее mcu hash (32 байта)
        8d 8e 99 80 5d 1e 22 89 c5 41 12 5d 5a dd 5d d5 30 89 4c c8 50 0d 03 55 41 b8 c0 a5 96 1e c0 5d
        d3    - контрольная сумма

```

Далее полученный хеш проверяется с сохраненным:

```
3.verify
!!!hash equal !!! 
check psk: psk is valid!
Production Process...Success!
```

Проверка PSK пройдена.

---

### Reset sensor

```
enter
--- to get CHIP ID
--- SetIdle

write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    a2 03 00 01 14 f0
        a2    - cmd (?)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0114  - payload (reset device, reset_flag 1)
        f0    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 a2 07 4e
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        a2    - cmd (?)
        07    - cfg flag 0x7
        4e    - контрольная сумма

read
    a0 07 00 a7
        a0    - флаг MSG_PROTOCOL
        0700  - полная длина следующего пакета в LE-notation
        a7    - контрольная сумма

    a2 04 00 01 00 08 fb
        a2    - cmd (?)
        0400  - длина последующего с контрольной суммой сообщения в LE-notation
        010008 - CHIP_RESET::0x010008
        fb    - контрольная сумма

```

#### read register - MILAN_CHIPID
```
write
    a0 09 00 a9
        a0    - флаг MSG_PROTOCOL
        0900  - полная длина следующего пакета в LE-notation
        a9    - контрольная сумма

    82 06 00 00 00 00 04 00 1e
        82    - cmd (regrw ?)
        0600  - длина последующего с контрольной суммой сообщения в LE-notation
        0000000400 - ???
        1e    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 82 07 6e
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        82    - cmd (regrw ?)
        07    - cfg flag 0x7
        4e    - контрольная сумма

read
    a0 08 00 a8
        a0    - флаг MSG_PROTOCOL
        0800  - полная длина следующего пакета в LE-notation
        a8    - контрольная сумма

    82 05 00 a2 04 25 00 58
        82    - cmd (regrw ?)
        0500  - длина последующего с контрольной суммой сообщения в LE-notation
        a2 0425 00 - Chip ID: 0x2504
        58    - контрольная сумма
```

### get OTP (one-time programmable memory)

```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    a6 03 00 00 00 01
        a6    - cmd (get otp)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0000  - payload
        01    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 a6 07 4a
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        a6    - cmd (get otp)
        07    - cfg flag 0x7
        4a    - контрольная сумма

read
    a0 44 00 e4
        a0    - флаг MSG_PROTOCOL
        4400  - полная длина следующего пакета в LE-notation (68)
        e4    - контрольная сумма

    a6 41 00 53 34 30 36 36 36 2e 00 0a 7d 82 b3 72 a0 46 0a 51 07 05 0e 7d 4b 17 27 41 02 9a 0c f1 80 7f 0c 07 81 30
    38 e4 80 dd fc 0a be bb 44 01 bb b3 b5 b3 b3 b3 b5 b3 b3 41 33 e4 1b dd 22 0c f0 17 db 1c
    
        a6      - cmd (get otp)
        4100    - длина последующего с контрольной суммой сообщения в LE-notation (65)
        53 34 30 36 36 36 2e 00 0a 7d 82 b3 72 a0 46 0a 51 07 05 0e 7d 4b 17 27 41 02 9a 0c f1 80 7f 0c
        07 81 30 38 e4 80 dd fc 0a be bb 44 01 bb b3 b5 b3 b3 b3 b5 b3 b3 41 33 e4 1b dd 22 0c f0 17 db
            - sensor OTP::0x5334303636362e000a7d82b372a0460a5107050e7d4b172741029a0cf1807f0c07813038e480ddfc0abebb4401bbb3b5b3b3b3b5b3b34133e41bdd220cf017db
              хранится в C:\ProgramData\Goodix\goodix.dat (первые 64 байта в файле)
        1c      - контрольная сумма   
        
    смотри third party, там все написано 
```

### Reset sensor (2)

### setmode: idle

```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    70 03 00 14 00 23
        70    - cmd (setmode: idle)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        1400  - payload (?)
        23    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 70 07 80
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        70    - cmd (setmode: idle)
        07    - cfg flag 0x7
        80    - контрольная сумма
```

### Send DAC

```
write
    a0 0c 00 ac
        a0    - флаг MSG_PROTOCOL
        0c00  - полная длина следующего пакета в LE-notation
        ac    - контрольная сумма

    98 09 00 38 0b b5 00 b3 00 b3 00 ab
        98    - cmd (send dac)
        0900  - длина последующего с контрольной суммой сообщения в LE-notation
        380b  - dac 0xb38
        b500  - dac1 0xb5
        b300  - dac2 0xb3
        b300  - dac3 0xb3
        ab    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 98 07 58
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        98    - cmd (send dac)
        07    - cfg flag 0x7
        58    - контрольная сумма
        
read
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    98 03 00 01 00 0e
        98    - cmd (send dac)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0100  - результат (?)
        0e    - контрольная сумма
```

### Upload MCU config

```
write
    a0 e4 00 84
        a0    - флаг MSG_PROTOCOL
        e400  - полная длина следующего пакета в LE-notation (228)
        84    - контрольная сумма

    90 e1 00 70 11 74 85 00 85 2c b1 18 c9 14 dd 00 dd 00 dd 00 ba 00 01 80 ca 00 04 00 84 00 15 b3
    86 00 00 c4 88 00 00 ba 8a 00 00 b2 8c 00 00 aa 8e 00 00 c1 90 00 bb bb 92 00 b1 b1 94 00 00 a8
    96 00 00 b6 98 00 00 00 9a 00 00 00 d2 00 00 00 d4 00 00 00 d6 00 00 00 d8 00 00 00 50 00 01 05
    d0 00 00 00 70 00 00 00 72 00 78 56 74 00 34 12 20 00 10 40 5c 00 00 01 20 02 38 0b 36 02 b5 00
    38 02 b3 00 3a 02 b3 00 2a 01 82 03 22 00 01 20 24 00 14 00 80 00 01 00 5c 00 00 01 56 00 04 20
    58 00 03 02 32 00 0c 02 66 00 03 00 7c 00 00 58 82 00 80 1b 2a 01 08 00 54 00 10 01 62 00 04 03
    64 00 19 00 66 00 03 00 7c 00 00 58 2a 01 08 00 52 00 08 00 54 00 00 01 66 00 03 00 7c 00 00 58
    00 53 66 8f
        90   - cmd
        e100 - длина последующего с контрольной суммой сообщения в LE-notation (225)
        70 11 74 85 00 85 2c b1 18 c9 14 dd 00 dd 00 dd 00 ba 00 01 80 ca 00 04 00 84 00 15 b3
        86 00 00 c4 88 00 00 ba 8a 00 00 b2 8c 00 00 aa 8e 00 00 c1 90 00 bb bb 92 00 b1 b1 94 00 00 a8
        96 00 00 b6 98 00 00 00 9a 00 00 00 d2 00 00 00 d4 00 00 00 d6 00 00 00 d8 00 00 00 50 00 01 05
        d0 00 00 00 70 00 00 00 72 00 78 56 74 00 34 12 20 00 10 40 5c 00 00 01 20 02 38 0b 36 02 b5 00
        38 02 b3 00 3a 02 b3 00 2a 01 82 03 22 00 01 20 24 00 14 00 80 00 01 00 5c 00 00 01 56 00 04 20
        58 00 03 02 32 00 0c 02 66 00 03 00 7c 00 00 58 82 00 80 1b 2a 01 08 00 54 00 10 01 62 00 04 03
        64 00 19 00 66 00 03 00 7c 00 00 58 2a 01 08 00 52 00 08 00 54 00 00 01 66 00 03 00 7c 00 00 58
        00 53 66 - mcu config (224)
        8f   - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 90 07 60
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        90    - cmd (upload mcu config)
        07    - cfg flag 0x7
        60    - контрольная сумма

read
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    90 03 00 01 00 16
        90    - cmd (upload mcu config)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0100  - результат (?)
        16    - контрольная сумма
```

### Init TLS - Get TLS handshake package

> TODO выяснить от чего меняется содержимое client hello
> TODO декодировать все пакеты tls через парсер
> https://tls12.xargs.org/#server-hello/annotated
> https://williamlieurance.com/tls-handshake-parser/

> https://aistudio.google.com/app/prompts?state=%7B%22ids%22:%5B%221eL109UOXNQUWn3T6FnA2gKBpy25bIkjp%22%5D,%22action%22:%22open%22,%22userId%22:%22108801036010063453123%22,%22resourceKeys%22:%7B%7D%7D&usp=sharing
> https://community.netwitness.com/s/article/DecryptIncomingPacketsTLS1-2
```
1. получить Client hello

write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    d1 03 00 00 00 d7
        d1    - cmd (get tls handshake)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0000  - payload
        d7    - контрольная сумма

not to wait for ack

read
    b0 34 00 e4
        b0    - флаг TLS
        3400  - полная длина следующего пакета в LE-notation (52)
        e4    - контрольная сумма

    16 03 03 00 2f 01 00 00 2b 03 03 2d f4 51 58 cf 8c b1 40 46 f6 b5 4b 29 31 03 47 04 5b 70 30 b4
    5d fd 20 78 7f 8b 1a d8 59 29 50 00 00 04 00 a8 00 ff 01 00               - tls handshake client hello package (52)
        [
            {
                "ClientHello": {
                    "version": "Tls12",
                    "random_data": "2df45158cf8cb14046f6b54b293134745b7030b45dfd20787f8b1ad8592950",
                    "session_id": "",
                    "cipherlist": [
                        "0x00a8(TLS_PSK_WITH_AES_128_GCM_SHA256)",
                        "0x00ff(Unknown cipher)" TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                    ],
                    "compressionlist": [
                        "Null"
                    ],
                    "extensions": []
                }
            }
        ]


2. отправить server hello

write
    b0 56 00 06
        b0    - флаг TLS
        5600  - полная длина следующего пакета в LE-notation (86)
        06    - контрольная сумма

    16 03 03 00 51 02 00 00 4d 03 03 9c 45 f7 ca 9a 9e b1 ec e4 3f d4 b4 4c 39 72 22 e6 7d 3c e8 2b
    66 50 80 57 46 a4 17 13 71 b7 8c 20 92 4f f3 83 b8 15 a9 20 19 0c 93 4a 20 4f f3 a7 1b fd 2d 40
    03 cb 18 37 81 b9 6b ce 7c 04 b9 9e 00 a8 00 00 05 ff 01 00 01 00         - tls handshake server hello package (86)
        [
            {
                "ServerHello": {
                    "version": "Tls12",
                    "random_data": "9c45f7ca9a9eb1ece43fd4b44c397222e67d3ce82b6650805746a4171371b78c",
                    "session_id": "924ff383b815a92019c934a204ff3a71bfd2d403cb183781b96bce7c4b99e",
                    "chosen_cipher": "0x00a8(TLS_PSK_WITH_AES_128_GCM_SHA256)",
                    "chosen_compression": "Null",
                    "extensions": [
                        "TlsExtension::RenegotiationInfo(data=[])"
                    ]
                }
            }
        ]


3. получить server hello done

write
    b0 09 00 b9
        b0    - флаг TLS
        0900  - полная длина следующего пакета в LE-notation
        b9    - контрольная сумма

    16 03 03 00 04 0e 00 00 00


4. Client Key Exchange

read
    b0 1a 00 ca
        b0    - флаг TLS
        1a00  - полная длина следующего пакета в LE-notation (26)
        ca    - контрольная сумма

    16 03 03 00 15 10 00 00 11 00 0f 43 6c 69 65 6e 74 5f 69 64 65 6e 74 69 74 79

      16 03 03 00 15  - Handshake, TLS 1.2, Длина 21 байт.
      10              - Handshake Type = Client Key Exchange (16).
      00 00 11        - Длина сообщения Client Key Exchange = 17 байт.
      Для PSK (RFC 4279): Это сообщение используется для передачи идентификатора PSK.
      00 0f           - Длина PSK Identity = 15 байт.
      43 6c 69 65 6e 74 5f 69 64 65 6e 74 69 74 79  - PSK Identity = "Client_identity" (в ASCII).

    Значение: Вот где клиент передает свой идентификатор!
    Этот способ (передача identity в ClientKeyExchange вместо ClientHello extension) используется в RFC 4279.
    Это объясняет отсутствие расширения в ClientHello.
    Сервер теперь знает, какой PSK искать у себя (по строке "Client_identity").


5. Change Cipher Spec (client -> server)
Значение: Клиент сообщает серверу, что все последующие сообщения от него будут зашифрованы с использованием 
согласованных ключей (выведенных из PSK, Client Random, Server Random с помощью PRF/SHA256).
    
read
    b0 06 00 b6
        b0    - флаг TLS
        0600  - полная длина следующего пакета в LE-notation
        b6    - контрольная сумма

    14 03 03 00 01 01
      14 03 03 00 01: Change Cipher Spec, TLS 1.2, Длина 1 байт.
      01: Change Cipher Spec payload.


6. зашифрованное сообщение Finished от клиента

read
    b0 2d 00 dd
        b0    - флаг TLS
        2d00  - полная длина следующего пакета в LE-notation (45)
        dd    - контрольная сумма

    16 03 03 00 28 00 00 00 00 00 00 00 00 1a e7 d2 ec 99 bc 03 c4 2c b0 3f b0 36 d5 16 24 27 2f c6 0a db 73 10 4a e1 7d eb 51 78 08 1f c7

      16 03 03 00 28: Handshake, TLS 1.2, Длина 40 байт.
      Это зашифрованное сообщение Finished от клиента. Оно шифруется с помощью AES_128_GCM и ключа client_write_key.
      Структура данных AES-GCM в TLS 1.2: explicit_nonce (8 байт) + ciphertext (содержит зашифрованное Handshake сообщение) + auth_tag (16 байт).
      00 00 00 00 00 00 00 00: Explicit Nonce (часть IV, здесь это просто номер записи 0).
      1a e7 ... 16 24 (16 байт): Зашифрованные данные. Они содержат:
      Handshake Header (20 00 00 0c): Тип Finished (20), Длина 12 байт.
      Verify Data (12 байт): MAC (вычисленный PRF/SHA256) всех предыдущих сообщений рукопожатия.
      27 2f ... fc7 (16 байт): GCM Authentication Tag. Гарантирует целостность и подлинность зашифрованных данных и Nonce.

Значение: Клиент доказывает, что он правильно вычислил ключи (т.е. знает PSK) и что рукопожатие не было подделано.
Расшифровка: Невозможна без знания Pre-Shared Key (PSK), который использовался для генерации сессионных ключей.


7. Change Cipher Spec (server -> client)
Значение: Сервер сообщает клиенту, что его последующие сообщения будут зашифрованы.

write
    b0 06 00 b6
        b0    - флаг TLS
        0600  - полная длина следующего пакета в LE-notation
        b6    - контрольная сумма

    14 03 03 00 01 01
      14 03 03 00 01  - Change Cipher Spec, TLS 1.2, Длина 1 байт.
      01              - Change Cipher Spec payload.


8. зашифрованное сообщение Finished от сервера

write
    b0 2d 00 dd
        b0    - флаг TLS
        2d00  - полная длина следующего пакета в LE-notation (45)
        dd    - контрольная сумма

    16 03 03 00 28 00 00 00 00 00 00 00 00 ef 3e db fd 53 50 df e4 f2 8e 82 fd e8 8d a8 f7 1d 58 8f 15 11 51 59 d5 01 68 40 84 2f 7b fd 76

      16 03 03 00 28: Handshake, TLS 1.2, Длина 40 байт.
      Это зашифрованное сообщение Finished от сервера. Оно шифруется с помощью AES_128_GCM и ключа server_write_key.
      Структура аналогична клиентскому Finished:
      ef 3e ... df e4 (8 байт): Explicit Nonce сервера (номер записи 0).
      f2 8e ... a8 f7 (16 байт): Зашифрованные данные (Handshake Header 20 00 00 0c + 12 байт Verify Data сервера).
      1d 58 ... fd 76 (16 байт): GCM Authentication Tag сервера.

Значение: Сервер успешно расшифровал и проверил Finished клиента (значит, PSK и ключи совпали) и отправляет свое подтверждение. Рукопожатие успешно завершено.
Расшифровка: Невозможна без знания Pre-Shared Key (PSK).


write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    d4 03 00 00 00 d3
        d4    - cmd (?)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0000  - payload
        d3    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 d4 01 22
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        d4      - cmd (?)
        01      - cfg flag 0x1
        22    - контрольная сумма

tls handshake done

```

### Get MCU config (2)

### Get imagebase

#### setmode: Fdt manual

```
setmode: Fdt manual
switch to FDT mode 3

write
    a0 12 00 b2
        a0    - флаг MSG_PROTOCOL
        1200  - полная длина следующего пакета в LE-notation (18)
        a6    - контрольная сумма

    36 0f 00 09 01 00 00 00 00 00 00 00 00 00 00 00 00 5b
        36    - cmd (fdt manual)
        0f00  - длина последующего с контрольной суммой сообщения в LE-notation (15)
        09 01 -
        00 00 00 00 00 00 00 00 00 00 00 00 - data sent::0x000000000000000000000000
        5b    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 36 01 c0
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        36    - cmd (fdt manual)
        01    - cfg flag 0x1
        c0    - контрольная сумма

read
    a0 14 00 b4
        a0    - флаг MSG_PROTOCOL
        1400  - полная длина следующего пакета в LE-notation (20)
        b4    - контрольная сумма

    36 11 00 00 01 00 00 61 01 87 01 4a 01 6f 01 4e 01 6e 01 ff
        36      - cmd (fdt manual)
        1100    - длина последующего с контрольной суммой сообщения в LE-notation (17)
        00 01   - IrqStatus:0x100
        00 00 - touchflag 0x0
        61 01 87 01 4a 01 6f 01 4e 01 6e 01 - received fdt base::0x610187014a016f014e016e01
        ff      - контрольная сумма (null)

IRQ for fdt-manual, get fdt-up base, current mode is fdt-manual, touchflag 0x0
```

### setmode: nav

#### TODO получить незашифрованный nav image

```
enter, Mode 5, Type 0, base_type 0
setmode: nav
gf_get_navbase

write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    50 03 00 01 00 56
        50    - cmd
        0300  - полная длина следующего пакета в LE-notation (18)
        0100  - 
        56    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 50 01 a6
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        50    - cmd ()
        01    - cfg flag 0x1
        a6    - контрольная сумма


recvd data cmd-len: 0x50-2410
--- recv nav data......length:2410

2404 2404 3200
Regroup pixels:1600

read
    a0 6d 09 16
        a0    - флаг MSG_PROTOCOL
        6d09  - полная длина следующего пакета в LE-notation (2413)
        16    - контрольная сумма

    50 6a 09 00 00 00 00 00 37 ef b4 7f 92 78 f9 b7
    ...
    b3 0b 0b 24 40 a7 94 39 d6 41 1b 2c 88 (2413)
        50    - cmd ()
        6a09  - длина последующего с контрольной суммой сообщения в LE-notation (2410)

00 00 00 00 00

37 ef b4 7f 92 78 f9 b7
14 9f a3 8a 8a 0b 1c aa a8 ba 8a d3 0f a8 af fb
3a f4 3c b3 b8 cb 4b 73 a4 b2 ba 4b cb 58 d4 bd
bf 7b fb d3 df c2 c1 7b 7b d8 eb ba be cb bc 30
28 c0 c7 4c 3c 4b 48 bf be fc bc 23 2b c6 c4 fc
bc 4b 47 c0 c5 cc 4c 9f ef c8 c1 fb 8c 70 23 c4
be 0c cb bf 14 b1 a1 8a c7 d7 b8 7d 96 48 f9 eb
1f 9c a4 8a c9 df 24 aa a8 4a 0a 97 10 aa ad 8b
8a dc 60 b4 b5 3b fb 78 73 b0 b5 cb cb 80 83 ba
bf bb 4b af a3 bc bf 8b cb eb af b9 c2 3b 8b d3
03 bc c0 7c fc 14 ff bc be bb cb d3 00 c2 c1 3c
8c 28 13 c2 c2 7c fc 13 d8 c3 bf fb 8c 43 1c bc
b9 7c 4b 94 0c ae a0 ca b8 47 eb 84 96 c8 49 d0
d8 9c a2 c9 f9 fb 3c a6 a4 ba ca 7b c8 a5 ac fa
8a cb bb b5 b2 8a fb 43 8c b0 b2 fb fb 53 78 b4
bb fb fb 78 c7 b6 b8 fb 0b c7 c3 b9 bf 7b 8b af
8b bf bd 3b 7b e3 d3 bb bd fb 3c 0b b7 ba bc 7b
7c 17 ef bb ba fb 4b db 9b bc be bb bb b3 a8 b8
bf 3b 3b 1f bf a7 9c 09 b7 b8 af 7b 94 38 39 8c
13 98 9e ca 0a 30 d7 a1 a2 79 7a 37 73 a6 a8 0a
8a 74 73 b0 b0 0a 4b 0b 33 ab b3 0b bb 0b 2b b6
b0 bb 3b 50 44 b1 b4 4b bb 94 40 b7 b3 7b bb 77
93 b8 b4 0b 7b 53 57 b6 ba 0b 0b 2b 53 b9 b4 fb
bb 7b 7b b9 bc 8b bb 83 68 b9 b8 0b 3b 38 5f b4
b4 fb 4a db 68 a6 96 c9 07 6c bb 77 92 f8 09 7c
a3 9c a0 39 f9 cb a4 a2 a3 39 ba 88 97 a2 aa 3a
4a 6c 9f ac af ba 7a c3 14 b1 ae 8b 7b 5f 8c b5
b4 8b cb 5b 9f b3 b2 3b 4b 6f 60 b4 b7 3b fb 27
83 b4 bb 0b bb 63 93 b7 b8 bb bb a7 48 b5 ba 7b
3b 97 a8 b7 b8 cb bb 93 8b b9 b9 7b fb 64 77 b3
b3 0b ba bf 88 ab 98 c9 b7 b8 e4 7b 96 88 39 cb
ff a0 9e f9 7a 04 17 a5 a5 3a 8a 8f c0 a9 ac fa
4a cb d4 ae b5 4a ca fb 2f b2 b1 bb 7b 60 a4 b5
b8 3b fb 48 88 b7 bb cb fb 7b 7b b6 b9 7b 3b 80
cb bb b8 fb cb 9c b7 b8 b6 bb 3b b3 9f b8 b9 bb
cb b4 bf b7 b9 3b cb 93 98 ba b9 8b cb 4b 87 b2
b3 8b 7b 07 6c a9 96 f9 37 b0 af 7b 94 88 39 93
c3 9c 9c f9 b9 cc 4f a1 a3 ba ba 5f 7c a2 ab ba
ca a4 94 aa af 7a ca ff 44 b5 b0 0b fb 74 4b b4
bd 8b 3b 70 7b b7 b6 8b fb 73 33 b8 b9 fb 0b 77
94 bc b9 7b 3b 84 af b4 bc fb 4b ac 48 bc ba 0b
3b af db bc b7 3b 8b 88 57 b8 b7 fb bb 83 7f bb
b2 fb 0a e4 5f a8 96 49 c7 6b ab 76 93 88 89 6c
8f 99 9b f9 c9 cf b7 9e 9e 39 0a 37 77 a4 a5 8a
8a a4 dc a9 b3 ca 7a b8 24 ab ab 8b 8b 2b 14 b2
b4 bb 3b 4f 58 b1 b0 8b bb 57 44 b3 b4 3b 3b 2f
40 b5 b5 4b 7b 3f 73 b6 b1 4b fb 18 37 b4 b7 7b
cb 6b 68 b6 b5 0b 8b 77 38 b7 b5 cb cb 24 e8 ac
af 8a 4a 9b f7 a0 8f b8 f7 af 8c 7a 93 48 49 8f
9c 9a 9c c9 3a 28 08 9d a2 3a 3a 2b c8 a7 a9 7a
8a 7b 73 ad ac ba 3a d4 28 af b1 3b ba f7 7b b7
bb cb bb 1c 53 b3 b3 7b 0b 64 47 b4 b7 8b 3b af
57 b8 b8 7b 4b 94 73 b9 b9 8b 0b 83 83 bd b9 4b
fb cc 6f b6 ba bb 0b 87 78 bb b7 4b 7b 47 6c b2
b1 3b 7a c0 67 a3 96 79 b7 ab cc 7a 92 38 79 90
bb 99 9b f9 39 e8 5f a1 a4 7a fa 7f 88 a6 a7 3a
7a bf 9b ad b0 ca 4a fc 64 b3 b0 3b fb 1f 64 b7
ba 0b fb 80 6f b4 b6 bb cb ec 6f b4 b9 fb 7b 98
a8 b6 b4 7b 7b b8 a8 ba b9 fb bb 8b 7c ba b8 cb
fb 9f 6f b7 bc 8b fb 4f 78 b9 ba 4b fb 63 7c b2
b3 7b 8a c7 5b a1 95 c9 37 df b7 7e 90 38 79 70
78 96 9c b9 49 b4 e8 a1 a3 f9 ba 6f 57 a4 a5 7a
3a e7 bc af b0 0a 0b 24 0f b0 b3 fb 0b 33 3b b5
b7 8b 3b 48 a3 ba b5 fb 4b e0 64 b1 b4 fb fb a0
44 b6 b3 bb 3b a4 97 b5 b6 3b 3b 73 4c bc b9 cb
7b b4 83 b8 b5 bb 4b 63 63 b5 b7 cb 3b 87 57 b3
ad bb 8a d7 83 a3 98 49 87 78 90 77 8e b8 49 1f
83 97 96 89 f9 b3 b3 9e a1 49 fa 28 68 9d a6 3a
4a 74 5c a8 ab 3a 0a d3 27 a9 ae cb 4b 2f f3 b3
af 0a 7b 23 23 b0 af fb bb 44 6f b5 b7 0b 0b 14
5f b5 af fb 8b 77 48 b0 b8 8b cb 2f 43 b5 b3 bb
fb 4c 60 b4 b6 0b 8b 53 34 b7 b6 4b 4b 2b 27 ac
ac fb 7a cf d3 a4 8d 48 87 3c a8 73 8c 48 09 30
63 91 9a 09 49 8b db 9c 9d b9 4a 04 33 a4 a9 3a
4a 9f 9c a8 ae 8a 8a e3 f7 a8 b1 4a bb 20 0b b4
b2 7b bb 1f 73 b1 b4 3b 3b 4f 2b b7 b5 0b 3b 1c
68 b5 b4 0b 4b a3 64 b6 b8 fb fb 87 40 ba b7 7b
8b a8 6c b5 b4 fb 7b 9f 08 b8 b8 fb 7b 6b 47 b2
b1 7b 8a ec 5b a4 95 b9 47 c3 04 7c 95 f9 09 b7
f0 9b 9d 39 8a 1b e4 a5 a4 c9 fa c8 84 a5 ad 7a
3a ff eb b0 b4 fa cb 5f 90 b3 b2 bb 7b 63 63 b9
b9 bb cb 6c cc b5 b9 cb 3b 9f 5f bb b8 7b 4b 5b
b7 b8 ba 4b 3b f0 ab bc b9 3b 7b 8b 73 bd b9 8b
7b c0 fc bb bd fb bb 83 ab ba bb 3b bb 90 b3 ba
b4 8b bb 24 db aa 9d b9 47 68 80 76 8c b8 39 88
78 97 9c 39 39 b4 07 9e a0 ca fa 97 1b a2 ac 8a
fa 48 8f a8 ac ba 4a db fc ad ae 7a 4b 07 2b b2
b7 0b 7b 0f 14 b1 b4 cb cb 2c bc b3 b4 fa bb 33
27 b6 b3 cb 4b 2b 4f b7 b1 fb 3b 24 14 b0 b0 4b
fb 0f 0c b1 b2 4b fb 14 18 b4 b2 cb 4b 3f 0f aa
ad cb 0a 8c 14 a4 91 89 c7 3f 6c 73 90 48 39 34
cf 96 9c b9 39 d0 88 a2 9b 89 3a 48 43 a1 a1 3a
3a cb 8b ab aa fa ca 8f 03 a9 a8 fb ba bc 17 af
ae fb 0a f4 e4 b2 b8 ba cb 50 1c ae ad 4b cb 2f
7c b2 b5 3b fa e3 28 af af cb bb 1f 1c b6 b2 0b
0b 68 7b b2 b1 3b 8b 1b a8 ad b3 4a 4a ec f0 ae
ae ba 8a a0 0b a1 91 09 87 9b 74 79 8b b8 09 74
a8 95 98 89 79 7c e0 9f a1 09 3a 3f a3 a5 a8 fa
3a b3 c4 ac b1 fa 7a d3 07 b1 b1 8b bb 48 40 b8
b9 4b fb 64 3f b4 b6 4b cb 4c 70 b3 b9 8b cb 50
87 ba b3 8b bb 60 3c b6 b8 cb 7b b4 63 b6 bd 0b
bb b7 a7 b9 b5 3b 7b 8c 7f b8 b5 fb 7b 8c 48 b8
b0 7b 0b 04 88 a2 98 b9 77 a8 c4 7a 92 08 89 5f
c3 98 9c 89 89 ff ec a2 a2 b9 ca 5f 88 a4 ab 3a
7a b3 fc aa b1 4a ba fb 07 b1 b0 4b 0b 2b 28 b2
b6 7b 4b 53 44 b4 b3 cb fb 6f 77 b3 ba 3b cb 78
74 b8 b5 fb bb 7f 98 b9 b8 bb bb 87 68 ba bc 4b
3b bb af b9 b9 7b fb c7 9c bc b7 bb 3b 8b 53 b6
b0 0b fb 57 a8 a4 9a 79 b7 9c b0 79 8f b8 c9 57
8c 97 9c 49 b9 cc 03 9c 9e ba fa 60 5f a1 a7 4a
ba a0 a3 ac aa ba 7b 00 e7 af ad 4a 0b 33 cf b1
b1 7a 8a cc 70 b2 b5 cb fb 93 60 b1 b6 bb 3b 04
68 b5 b8 4b 0b 3b 5c b2 af 4b 3b 3f 94 b5 b5 3b
7b db 37 b7 b1 8b 8b 63 77 b8 b6 8b 7b 0f 44 b2
b1 0b ba c3 eb a3 8e b8 37 48 af 74 8e f8 89 94
87 93 9a 79 49 a4 0f 9b 9e 8a 4a 4c 2f a5 a8 7a
ba 6f 90 a6 b0 7a ba ac 0c ae ae 7b 7a b3 e7 b3
b3 0a 3a f8 ff ae b4 4a bb 17 d7 b2 b7 7a 7b 0b
37 b3 b2 7b ba f8 ff af b8 4a cb 67 33 b3 b3 7b
3b 17 7b b5 b5 0b ba b7 50 b4 b3 fb 7b 60 54 b3
af bb fa a3 18 a6 91 b9 07 73 8c 77 89 38 09 44
bb 93 9b 79 b9 ab d8 9d a1 09 f9 ff 5f a3 a2 ca
0a 3c 7b ad b1 3a fa a4 bc ac aa 4a 7b 14 0c b1
b4 3b 3b 43 4c b3 b4 7b 0b 57 3f b1 b9 3b 0b 64
2b b9 b4 cb 4b 1f 64 b4 b6 7b cb 6f 07 b4 b2 0b
3b 80 77 b8 b6 fb 0b 28 4f b6 b5 cb 7b 53 f4 b1
b3 4a 7a db 43 a6 94 39 87 6b ec 76 92 b8 89 a4
cf 96 a0 49 49 cc 27 a4 a1 3a 8a 48 5c a4 a8 7a
4a af c4 ad b0 4a 0a ff 23 b0 b4 3b 3b 2c 4f b3
b8 fb bb 3f 4b b7 b2 8b 8b 9b 6b b7 b9 3b bb 37
97 b7 b7 7b fb af a8 b6 b8 8b 8b d4 5b bc b5 fb
8b c0 af ba ba bb fb 7c 2f bb bc 8b fb 48 4c b3
b2 8b 7b 13 57 a9 95 89 87 7f a8 77 8f f8 c9 54
c8 98 a0 49 49 c3 17 a1 a4 0a 4a 67 a7 a8 a4 0a
8a 9c e8 ad ae 7a 7b 23 3f b1 b0 7b 8a fc 47 b5
b8 8b bb 20 8b b3 b3 3b bb 8c 7f b8 b9 0b 3b 7c
7f bf b5 fb bb 1f 5b b6 b5 4b 8b 88 bf b4 b8 cb
8b 80 a0 b8 bb fb 7b 6f 77 be b7 8b cb 53 83 b3
b0 7b 7b 3f 8c a5 98 c9 37 57 58 75 8f 48 c9 5c
df 97 9d 89 49 d4 87 a2 a2 39 3a 73 8f a4 a5 ba
fa 68 98 aa ac 8a 3a c8 24 aa ae cb ba e8 3b b0
b2 fb 3a ef 6f b1 b0 cb 3b 2b 3b b3 b2 4b 7b 10
3c b0 b3 fb 8b 1f 67 b4 b4 8b 0b 2b 0f b8 b6 bb
3b 7f 43 b4 b1 3b fb 6f 14 b6 b3 cb cb 2b 03 b3
ad 7b 0a ab 2f 9f 93 09 77 7c bb 77 90 08 09 6c
8b 96 9e 79 79 f3 27 a4 a2 4a 4a 57 73 a7 a8 fa
fa 88 af ae b2 ca 3a bc 3c b0 b3 7b fb 48 30 b7
b7 fb 7b 2b b3 b4 b6 0b 7b b8 48 b6 ba bb 3b cb
a3 b9 bd 4b 3b 60 d8 b2 bb bb 7b 6f d3 b7 b9 8b
cb 6b db bb ba fb 3b a8 9b b7 b9 fb bb 8c 7f b9
b3 0b 0b 24 40 a7 94 39

d6 41 1b 2c    nav crc check ok

88
```

### setmode: Fdt manual

```
setmode: Fdt manual
switch to FDT mode 3

write
    a0 12 00 b2
        a0    - флаг MSG_PROTOCOL
        1200  - полная длина следующего пакета в LE-notation (18)
        a6    - контрольная сумма

    36 0f 00 09 01 80 b0 80 c3 80 a5 80 b7 80 a7 80 b7 2e
        36    - cmd (fdt)
        0f00  - длина последующего с контрольной суммой сообщения в LE-notation (15)
        09 01 -
        80 b0 80 c3 80 a5 80 b7 80 a7 80 b7 - data sent::0x80b080c380a580b780a780b7
        2e    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 36 01 c0
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        36    - cmd (fdt)
        01    - cfg flag 0x1
        c0    - контрольная сумма

read
    a0 14 00 b4
        a0    - флаг MSG_PROTOCOL
        1400  - полная длина следующего пакета в LE-notation (20)
        b4    - контрольная сумма

    36 11 00 00 01 00 00 60 01 87 01 4c 01 71 01 51 01 71 01 f6
        36      - cmd (fdt)
        1100    - длина последующего с контрольной суммой сообщения в LE-notation (17)
        00 01   - touchflag 0x0
        00 00   60 01 87 01 4c 01 71 01 51 01 71 01 - received fdt base::0x600187014c01710151017101
        f6      - контрольная сумма (null)
```

### Read register - fdt_delta

```
write
    a0 09 00 a9
        a0    - флаг MSG_PROTOCOL
        0900  - полная длина следующего пакета в LE-notation
        a9    - контрольная сумма

    82 06 00 00 82 00 02 00 9e
        82    - cmd (regrw ?)
        0600  - длина последующего с контрольной суммой сообщения в LE-notation
        0082000200 - регистр ?
        9e    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 82 01 74
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        82    - cmd (regrw ?)
        01    - cfg flag 0x1
        74    - контрольная сумма

read
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    82 03 00 80 1b 8a
        82    - cmd (regrw ?)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        80 1b - fdt_delta 0x1b
        8a    - контрольная сумма
```

### setmode: Image (read image)

```
write
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    20 03 00 01 00 86
        20    - cmd (image)
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        0100  - ???
        86    - контрольная сумма

вариант 1 - TLS активен:

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 20 01 d6
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        20    - cmd 
        01    - cfg flag 0x1
        d6    - контрольная сумма

read
    b0 2a 1e f8
        b0    - флаг ???
        2a1e  - полная длина следующего пакета в LE-notation (7722)
        f8    - контрольная сумма

    17 03 03 1e 25 00 00 00 00 00 00 00 01 89 42 81 b9 a0 20 84 27 79 81 0d 07 f1 4f 38 a6 aa 9c 2d 3f de 1e ad 7a 5d 87 48 5c 7a 7b 77 19 a8 77 ad 05 dd 2c d9 be b3 df 7c a9 14 a7 ad 15 bc e9 be
    5d 39 46 35 12 4a 00 e2 9c 8c e1 8a 08 5b 47 b0 67 d8 c2 f5 2c 0d 73 55 bb 39 17 16 9b 2f 73 29 7e ad 96 87 fe 94 e1 98 93 36 94 25 63 8a 19 60 80 19 6b fa 12 23 00 65 f5 dc c8 ee 21 4c c8 4a
    45 e3 70 65 38 e8 0e 52 aa 04 15 e6 54 45 39 b3 f4 cd c9 fb 4c cc c9 57 cd e6 ef 3f 50 03 cf 2e a8 3d 95 ae b2 50 6d b8 40 07 97 b9 fe 1b 2f a3 f4 bd ba 9d 3e 75 38 44 65 ed bb 15 70 c7 47 2d
    21 e7 33 be cb 91 68 c4 60 4c 31 0b f8 bd d2 6e 25 24 4b ab 4a 41 45 8e 69 d4 42 e6 64 55 ea 9d ed 3e 51 44 22 da 28 fd 72 fe 9d dc f6 e9 20 77 94 2a 95 ff 80 39 98 e0 5f e0 35 3b 57 53 bf b9
    02 df f9 d8 0f 42 74 67 4f 4b 1b f5 40 7e 44 48 34 33 7d c5 e8 a4 82 fb 4b 69 1c a2 e9 aa 2b cf da 70 9a 34 51 a4 84 f4 a4 3e d6 f3 09 a0 25 5d 96 13 b7 2e 28 da 33 99 eb 71 55 c7 84 e8 46 49
    16 de da 47 4a 64 03 57 dc f2 5b 0e 95 6e f7 9c fe 0b a1 ad 20 a9 c8 7b e4 46 6b da f8 5e 02 9a f3 dc 89 ed d3 90 7e 88 1a 1d 36 37 0b fe 6a 69 59 6b cf 83 1a 2f 50 fb e7 79 da 74 36 84 53 e1
    76 08 df 39 da 0f 83 e8 96 58 cb 1f 27 03 24 8a d3 cf 00 15 8c 25 31 ec 18 ca 30 59 46 4b 52 f9 b0 a7 50 dc 59 16 2e 8a bc 08 4b 47 c5 88 4c 96 7a 2d c0 ed f0 d5 c7 20 1c 9c 55 ee 84 89 8b 85
    63 e7 65 90 93 6b 3b 46 e1 eb 23 15 c0 e4 4d 79 2d 3a 4e 3d 8e 58 59 87 8e 11 7b 16 85 73 6c 43 7a 31 cd f5 d8 16 a2 cd ce ec 43 07 34 4e ea 77 58 48 21 65 19 65 5b 77 d1 db c7 cb b9 b9 1f b4
    cd c1 cb b5 55 29 d4 df ae 1e 90 da b9 5c af 6e b4 37 9c 06 e6 7b d3 b0 17 4d 36 7d bf 93 9c 13 b4 dd 74 32 5f d0 6c 21 3d bc 2a 41 36 c2 22 89 78 91 c9 c9 b9 14 6d ae bd 56 ad dc 6d 21 a5 90
    60 cc 20 57 2c 2c 6a 8d 51 df f0 f8 d9 cc ab 2b 55 41 b5 4a 93 0d 37 d4 15 e8 8c 6e e2 73 ab c4 8c 0c 5f 32 70 53 5b db b6 c3 0c bf 63 da cd 42 00 15 28 f6 39 b9 ee 11 29 1f a2 0e 18 b9 34 ef
    2f 9f da 87 21 1c 97 a4 9b cb b4 07 eb fc 48 1d a1 3a 0b 81 ff 66 41 1d 43 fb df f1 90 15 77 a1 67 59 53 f4 0f 6e 58 33 39 83 1d f3 af 10 e0 f9 72 93 06 06 7b e8 dc 1c 83 1c fd 3c 7c fb 77 f4
    8a 22 74 fe f3 48 9a df e4 83 fc a6 0d 0c 54 50 5d d7 50 9f f5 d6 0b fa 73 ed cb cc e3 66 44 f3 19 28 a1 5c 96 0c 22 b7 bb 0d e0 17 1c 72 7c 21 d5 41 de a4 da 86 f3 2a cf b4 20 f4 26 94 5c 20
    00 a5 d0 a4 36 89 f2 a1 c8 f8 90 67 ea 54 ba 19 c1 62 91 2d 1d f6 5d 93 cf 31 ee 32 44 d9 46 26 07 93 87 71 e8 fb 15 e9 e4 67 5b b2 27 eb 2d 7b 13 87 f8 6e 6d 53 35 f4 46 1d d5 fa 58 00 26 42
    aa 86 81 2f 17 3f e8 16 1c 67 ee 84 30 8b 45 ac e4 51 10 39 20 8f 56 42 74 27 4e da 0e 54 d9 25 9a ef 96 a6 27 99 e7 3f 80 4a fa 4b e7 08 b3 27 14 b7 86 aa 2d b5 fe 7e bd fd 84 84 25 dc e5 f4
    b0 db c8 c4 0f 60 ed 8c 2e 46 79 02 e8 d9 c7 c3 b9 16 8b 1a e4 41 1e 50 ab 49 4d be 65 06 ce c0 eb 03 e4 65 b6 38 4e d3 13 91 05 88 20 00 b8 26 de db a5 65 f3 71 ad d4 bf 93 26 86 d8 2f ea 79
    4f e0 44 e7 61 02 20 e0 2f 52 29 ae 0e 7d 8b ff 10 18 25 e4 7a f7 e9 b9 49 48 53 2b 4d 96 77 8b 58 c9 11 d0 a2 cf 56 2f bb 2b 8c 4a fc 19 27 86 88 23 f4 1e 9b 96 09 17 0f 39 00 45 24 c5 12 a6
    05 07 ec a3 7b a7 f5 1d d6 d4 2c 80 c6 bc 7e 3a 07 ad b7 6d 22 f5 1c cd 27 93 c0 c5 0a 0f 43 1e fd aa a5 e0 23 91 d0 87 9a 7f bf 97 40 db 70 f3 42 3d 81 81 e7 a9 b6 98 09 f0 70 17 d8 43 01 eb
    66 08 fd e7 3b b5 a5 7e 0e 5d 9b a5 6b cb ef 0a a6 53 50 06 18 b0 79 cf ca 6f d9 ee 0a 60 de d0 fa 29 1c 83 01 e0 2c cd b3 9a 19 a8 6c ff 61 56 24 df b3 a8 7f 7c 62 a4 30 f8 31 9c 3a 56 0a 28
    91 74 aa db 2a 48 0d ad 6d 20 51 13 3e d7 0f c4 05 1b b4 f1 56 c1 1b 34 b2 6c cf 5d d8 af bb cd 55 9f 20 5b b8 3f 21 52 87 a4 3c 4e 83 0e 1b 7b b8 84 36 81 42 c7 7b 3d a9 12 34 e9 98 72 f3 c6
    56 03 e1 42 4b 4d c5 b6 ac 16 02 1f 51 78 6e 0e 80 09 60 10 d3 eb 48 48 e9 26 85 fd a4 3d 27 8e 5e e9 60 05 e2 88 9c ef a1 73 b4 64 60 96 ac ff 95 49 5e 80 16 5a f9 10 3a 3f 30 dc b9 ec 82 49
    de 48 a8 8d 40 39 9f 5d 28 56 7e fd 5e b1 a4 91 36 60 d0 ea 25 f7 50 69 c0 23 ca 59 d2 65 9c 93 3b e1 47 9c f5 55 6b 58 9e 31 96 56 b1 d4 d4 d9 b8 19 ac 5d d6 b1 fb 75 a5 dc 92 0f 01 64 36 42
    62 3e 65 09 53 5c d0 70 57 ed 8b 80 4d 9b e9 c5 e6 bf 96 8b c8 d9 82 e3 e7 b5 e3 0d bb 70 06 a3 7f f3 ad ef dc a6 b3 3c 42 9f 9d d8 08 2b de db 65 05 2c 7f 58 0a 89 83 0e 1f 90 48 3c 29 9a 80
    83 fd f3 b3 2d 76 3a 7a ec c5 00 3c 83 10 57 e7 4d 58 32 ab 3d 2f 5c 3b 57 c1 00 ad 71 db 3e d2 a7 10 25 c7 4b f3 f0 43 56 ed b8 ed 28 01 5a 31 b9 1c 73 68 5b 5e d2 ac 35 36 60 89 7a 81 b3 b6
    54 d2 72 46 d7 f0 66 0d 18 71 26 29 2d 7a 7b 7a 33 a0 98 25 11 ba 4e 18 05 67 81 dd 42 6f 48 92 1e 72 56 b1 8b 6e 17 df 62 b3 51 87 b3 79 0e 9f 17 35 32 21 07 89 21 5a 71 63 6e f1 bb db 2f 16
    71 1b b1 e1 2d a7 6f 36 7f 89 29 43 f3 84 72 18 23 ec d3 9d 53 34 61 ff 84 4f cb 56 9b 6c 52 d0 be ad 2d 8a 58 41 59 b0 13 73 d9 84 f6 b2 0a 7b 26 35 78 ef 42 33 37 8d f0 e7 70 a0 8e 7a 5d 84
    fa ea 90 4d cc 88 6f 77 fc 74 ce 69 86 86 b2 16 7e d7 31 e9 a7 d2 eb 55 39 01 71 d1 f9 db 43 e9 a9 9c 97 41 2f 93 f0 b2 97 51 eb 71 b0 ab d3 db a3 f3 82 cf 89 fd d7 5a 74 3e bc a0 9d f6 8c 0b
    d2 bf b9 3c 8c a1 87 a4 2d 28 7b c3 bb 40 45 ac 98 24 52 d7 5c 22 c9 74 be ab 9b c9 b9 67 94 1b 21 b1 00 14 65 fb 47 98 f8 66 ca 91 33 50 7b 81 d9 76 3c 76 35 72 5d 5f c5 02 ae 2b 4b 46 b1 0c
    da df 44 08 c9 4c bc 1c 50 8b 3f fd 8f e1 d1 ce 04 85 45 30 d2 9b 4c 1a 69 3d d0 8d 3b 6b 47 28 7c 05 7e 67 6c 95 0c 81 9f b8 12 4d 9b 80 f9 e4 14 bf ee 55 49 29 9a bd 13 35 92 a5 56 37 ab 72
    4c fd 00 bc 66 ce 84 11 4b 3c 93 4f fb fe ee 45 a2 00 de 66 e0 22 d7 ea d4 e8 1b 6b 21 d5 ce fb 11 85 54 6c 73 e3 c3 15 17 4b d7 e1 57 aa f5 a4 b0 93 df bd bf 57 91 e4 81 ad 4a 30 8c 36 65 f6
    86 6b 30 75 99 a9 24 d1 24 36 1b 5b fd fd 50 9c 75 b2 5d 91 40 ff eb 7f cf 40 b9 fb 82 db 24 a3 ec 16 71 2e 0c 06 38 ad 2b 1c fd f0 93 65 9a ea e7 8d 28 e6 88 97 08 54 e3 4d fd 1b c8 f5 29 9e
    78 63 27 f0 56 bd ac 58 8c b0 1d 99 5d bb 64 6d 45 ed b0 9b 2c 6c 71 e4 73 ca 08 2e b8 6d f0 35 d6 d1 9b 71 65 23 6d 60 ef 73 04 a9 2a 49 0e 8f 46 90 63 24 f1 e8 ff e7 00 d6 bf 23 eb c3 95 78
    9b 13 f3 92 a0 56 57 03 19 e3 2d 81 75 28 59 95 f8 42 b0 1c 8b 33 2d 2b e0 49 19 0e c3 2d 3d f0 11 5a e4 43 cd f1 b6 d5 08 0c a2 ad bd 29 16 f7 bb 58 cf f2 0b 86 cb 3a f8 38 58 39 5a 33 17 71
    94 65 6a 9d 3f 39 ef 3f 75 90 68 e0 25 29 d1 f2 a3 6c 31 3d 10 e0 d8 e1 1e 1f f3 af ab fb 1c 92 2b ab 17 9a b5 49 5a 4c 1d ce 18 a0 be 5a d7 2a af 18 72 08 2e db 00 02 70 6e 08 d3 62 11 be 85
    0c a2 d2 56 31 a5 a4 e8 4a 06 c2 5d d6 f0 cb 21 09 4b 2b de 3e 8a d1 30 09 00 e7 83 f3 8e 4e 23 55 dc a4 6e ab 4e 9b c0 ed 6f 7b 2e 9b d0 aa 63 1b 4a 81 5c 7a 26 7d 44 63 8f 11 8a 4b f1 63 8d
    7e a9 cb 06 98 ae ec c7 14 1c 03 d3 b2 7b 97 2c fd 2e c6 94 36 43 72 31 1e 3f 01 f9 9a 3a 85 ea 68 07 ab 34 f2 c2 2c be 28 f4 fc 2b cd db 24 4d 0e d4 db b4 26 00 f0 9c ac 3b 52 24 0d 1d 99 7e
    bc db a8 98 67 7c e5 1c b8 6f 38 8b f0 f7 f5 03 cc 11 91 3f 99 a2 ba 74 1e a1 8a 9e ff 3b 73 47 8b 97 92 60 2c c8 fb 38 7b 16 89 07 a2 f5 c9 1c 81 a3 ca 78 68 1a f6 ab 4d eb 83 41 bb 49 44 5d
    08 67 74 cb 81 35 b2 6a 5e 86 e6 a4 94 40 92 fe bc 41 3e 54 3f 47 a1 80 9b b2 03 20 8c d2 11 7c c6 eb ad 7a d3 b5 73 d2 f9 3e 8a c7 e7 a5 b4 27 33 e5 b5 a3 90 2b ce 81 df 55 6b a7 a1 85 48 a2
    35 f3 a1 fe b4 5b 99 fa 25 34 47 b4 3a 25 e6 6a f0 33 a2 dc e4 e5 8d 42 5c 84 52 7f b2 50 ed ac c8 9b 0b 60 08 20 f6 0a e3 9a 22 9e c4 5a ab 9c 99 02 55 b8 18 e9 f5 8d 0f 2a ab cb 9c f8 91 3c
    84 c5 0d 96 a4 97 69 3d 3b 14 7a dd 6c d9 37 d6 c7 06 b8 98 ea b4 11 83 cd 4b 2a d5 d7 31 e3 f3 c2 6d 75 06 83 d1 9a 35 72 06 af 3a a9 79 55 b6 e4 a5 09 9d 71 e5 a5 40 07 42 82 67 18 76 3e c4
    4b 57 00 35 43 8d 4a 3b 04 99 29 55 ea 4f 6b 29 02 a0 d1 f0 9d a9 00 4f 42 1e 7b c2 66 37 bb c8 d8 7c 21 18 72 f0 94 29 c0 c2 f1 0c 2d 05 a6 a8 4d ba 58 54 da 1a e5 21 60 dc 0d 0a c5 99 65 8d
    06 50 04 96 08 7a 08 6b 74 4b a8 a9 b4 70 b6 06 94 05 cf 75 74 46 1a 76 55 1e c3 7a f5 82 c1 77 0b 1a 84 21 2a 73 b3 4e c2 da ee a7 c8 8b 27 59 a1 62 10 78 0c 57 5d 4c 03 3d 1a 28 33 49 1f c9
    5d 5d fe d2 30 e1 91 3f 99 1a ce 62 12 15 13 4d d6 ea 24 47 17 4a d1 80 b0 39 df db 1b b1 a8 45 10 dd 92 3e 56 bb 7a 39 e1 8d 51 74 7e 81 8a 9a 27 84 50 2f 34 6a 14 b4 bf 9a 82 22 f3 d9 22 e6
    86 80 b5 7f dd 43 0d a8 56 66 3c 1e b7 7c 56 f5 35 e6 72 14 e7 7c 97 cf 5d dc c5 01 55 ac b2 af 78 53 31 e9 23 f3 e6 d3 ac 35 a7 61 a8 af 46 44 a1 be 64 2d 70 1b 42 49 7d dd cd 49 f4 3f 2c 8c
    3a 20 c7 e3 91 a5 90 5a 5f 6d 07 38 b1 eb 89 ce 47 33 8d 6b 1e e5 9a 0a 87 46 4a 10 25 89 15 66 07 ae 4d a9 df 00 da 49 c4 8e 79 18 35 54 3b 7d f5 81 99 02 d3 1b 6b 44 8c 4b 1e e7 9f 4f 05 29
    6c 91 19 d3 72 6e e0 ab b1 a8 35 dd 73 df ea 30 e5 8c 4c 01 45 c9 41 a2 01 05 ea 07 ef 83 e2 61 89 9c 8d a6 71 29 ac 29 df 28 a3 5e 3f 99 10 63 89 f3 2b dc 3e 91 a3 6f 96 7c 79 b9 84 f3 ff 0b
    4d 3d 48 fa 56 0e f6 15 39 fe b8 38 a6 37 d8 b9 95 c0 60 0f 70 d3 ed cf 56 05 b3 d8 d9 16 61 16 68 28 ad cc 49 dc ba ce 5d aa 6b c9 a9 ec 00 75 93 e8 0b 2e 8c 5a 93 e9 71 68 26 48 01 4d 26 ea
    93 60 f6 69 91 bb f4 2e 4f 54 aa 69 de 0e 2b a0 4d 4d 7d 3f 79 3a 2a 47 6b af 60 b4 4c 57 54 c8 30 a2 d9 67 45 c9 32 97 70 31 4a 7c cc 86 e8 8a 93 16 0c 6e 98 23 1d 25 7d 49 b8 fd 07 4b 08 36
    03 09 1d d9 8c 64 1d b8 87 46 fc c9 9c c0 2b fa 2c e8 12 d5 bb 62 5f 99 2f 92 cf 5c e6 60 dd 16 47 77 38 7b 8a 6c 76 d8 48 ac 43 2d 1a 0b be e7 29 23 77 c0 28 71 f3 03 57 94 4e e2 aa dc 89 10
    9c 8f 2a ce 01 d3 14 c1 45 c8 96 6e 3c 14 ad d8 4b 79 9f 2f 2c c4 da 9b e5 a3 04 97 15 b5 cf 83 61 15 fb fc 3f 09 cf 9b d1 da 46 6b 7b 81 ef 4d 48 69 48 be 11 ad d7 a3 02 85 d2 a4 f3 0b be 27
    56 0f f0 42 8b fa 79 c6 d7 69 29 73 3e 5c ba 1c 4f 17 3a 6f b5 f0 aa 4d 51 2e a6 dd c1 b2 03 07 e6 df c3 f5 67 8b b8 cb 9e fd ae 5e 74 e3 52 35 4a 18 95 aa 54 67 41 a2 48 52 ce e9 91 11 50 8a
    66 7d e5 15 c3 2d 09 ef 8f 52 f7 eb 7b 32 35 e6 98 f5 2d 57 35 b3 85 17 e8 1b 4e 71 29 58 04 30 82 a3 b9 6c 44 93 3b 66 cc 68 c1 5e 82 eb 0b 1b c6 4e f8 d8 12 c2 6e 5e 87 1b 4e a7 19 9d 35 0e
    92 69 e6 59 98 13 ba 4d 15 28 5a cc 95 a1 7a 46 c5 8a b7 12 82 55 54 f3 5b 4d c0 82 e0 83 bd d3 70 83 b5 99 3d 5b 60 f5 f0 da 47 c6 e2 b9 5a 09 31 0a 2a b7 19 d6 ea 40 d4 99 e1 77 a3 0f 74 fb
    7f 23 48 92 63 89 28 b4 a3 75 27 48 54 82 07 d6 ac 6f ca 96 2b 94 e3 4f 94 41 00 b2 74 35 91 03 9f 33 0e 1a 47 e2 e3 6b b0 99 64 c1 ce 6a 47 35 1c a8 6a 2f 13 72 34 1f be ec 74 99 d4 5e 64 e1
    99 d4 c2 1d c9 49 a2 5d ac 66 07 19 2e 0d 73 59 39 e2 2c 70 12 bc e6 a3 b7 26 f4 ff 59 88 e6 fa cb 09 bf bf 2b 4b 7f fd 41 16 ac 61 9e 9d d0 b5 b9 f4 9a 5d 7c cb 74 a8 16 b4 83 87 9f 01 89 79
    04 15 3c d6 2b db fa 36 d9 a9 76 00 e8 a0 a2 d7 1b 94 a4 49 9a 34 f4 e3 ee 20 ae b8 46 aa b4 8e f6 87 7b 8d 33 3a 4d a4 3e 07 fb c6 9d 8b f6 df 28 0e c6 f8 e9 a2 b9 f7 eb f5 b9 93 f2 22 bc 1b
    81 7a 2b cd 60 4d 6d 06 18 70 ba aa 2b 16 3a e1 ed f6 ee e1 f0 4e d0 b2 46 26 2f c6 ab 07 02 6f cf eb d2 c7 a5 2a 85 9b d9 c0 b1 b2 d6 76 07 f3 3b 91 06 61 4a f9 d9 60 b4 a5 46 ff 3c 7a 25 47
    f0 da 58 67 f0 ae 38 ff 18 90 32 9d c2 77 2d 86 fe f0 ba fd 49 b4 d9 34 35 34 3b cf 4f b9 b3 67 f5 2a 0a 8b 93 0f c5 51 23 43 b1 9c 9a 42 cc c6 63 08 ee e5 0e 8a 98 8c 42 19 28 9b 24 34 71 6b
    23 76 d1 b9 0f ce 7e c9 f4 e5 6d 78 fe 3d 7a 34 92 a1 5d fc 7e 5a a3 b2 88 65 d6 84 1a 63 a0 04 9f 56 56 f0 e3 aa a3 2f 7d e2 04 41 1a e2 89 70 48 19 9a 4b fc dd 8a 59 fb cc c6 2d d5 e4 1d 5b
    8c e8 cd b3 0e d7 47 57 7b ec 99 4c 30 6b 40 0f 80 0f c3 73 b5 22 90 7a ae 85 03 ca 35 be 1f 10 4b e6 46 18 73 54 01 02 de 7a c6 94 4e f5 b1 88 35 d9 06 3d b7 50 c3 a8 ea d2 3a d7 d1 8c 85 89
    61 e5 37 9d b5 b4 6b 67 19 02 3e 55 b0 8f c7 78 80 99 cc 85 97 9c ca c1 fc db 82 7f 57 b0 f7 09 f6 6c b4 e4 1d 19 20 fe e4 15 d1 12 07 99 1b 2c e4 25 e3 9c 9c 76 e6 0b 6b 77 c6 2f 52 19 2b ac
    56 6b b0 61 88 0e b1 0b 98 fc 9d 59 81 0b 6d d9 02 87 30 af 9d 57 e2 f1 5e 5d 37 38 6e 2a 0e 62 49 d6 00 1b 11 8f 6d df ee e8 cc 73 20 24 f3 dc 65 36 29 33 2b f3 84 e7 5f 8b 39 91 40 6a 55 e4
    08 19 0e a9 b2 b0 94 6e 6b d5 f9 4c 83 11 1e 11 80 e8 fa e9 b3 5d 06 27 b2 db f3 4b 32 d6 e0 0e ec 25 1a d5 2a 49 1a af af 44 92 a9 be ce 4b 5a 14 ca 08 a6 af 09 54 f7 51 aa 42 5d a4 6a ca 1b
    c9 3b b7 e6 75 58 9c 4c 94 c3 55 89 85 08 e8 db 1d a9 93 ef 08 c0 d9 38 8b f5 08 4a 4a 51 d2 23 30 3b 44 05 06 54 7f 6a fb 2a 6a a3 ba 3d f9 2e db 45 fa 6c 26 d2 25 ad 77 42 7c b0 2e e9 f7 03
    c5 39 91 40 fc c7 30 76 7c 40 aa c4 3a e4 6e 5b 7d f9 d6 bf e3 02 f4 a9 d2 3e ac 21 04 b0 df 08 36 9d 4b 80 11 14 1c 53 37 d7 a2 3f 73 51 b3 77 77 70 06 32 70 f3 73 37 55 66 9a ff f0 00 61 b1
    18 34 56 fb 8f 59 18 44 c6 53 ce 3e 1b 75 62 25 eb 78 c5 52 d8 03 83 8e 80 39 6b e3 61 5c a1 d7 8d c9 74 94 63 74 e8 87 ed 13 a2 c9 c1 9f 71 ec b2 3b ef f4 ba d1 61 f4 dc df 2f 40 dc fa 31 9d
    3c 57 d3 e1 bc 2e 58 f4 a9 f7 4b 5e 80 58 22 56 ef 44 cb 79 a8 e0 19 58 1a d1 36 fc 29 5f 47 b7 6e d1 0f 73 af c3 dd 6a ed 31 62 1b b0 43 07 7e 66 e9 c1 35 d4 5e ab dc 6d 54 df 64 38 b6 37 8d
    42 d8 57 b2 ba e9 96 32 c0 6d a6 cb bc de 88 1b 8e 30 b6 49 b2 e4 ae 70 37 d4 dd b2 9d 07 a2 73 d2 e4 ee 85 df fc ea e3 62 85 aa fb 66 30 a5 95 4c 59 d5 1e 1a d0 27 19 40 e3 f9 a9 d2 12 a8 06
    b7 89 4b 4e f0 00 0d a3 ca 5d 96 22 04 2f 2d 35 fa 35 9c 54 06 5d 0f 3c 2e ea bd d3 4e 38 c5 61 1b 8e be 88 60 36 94 0e 2b e6 79 99 b1 91 e4 cb 4f 73 5e 57 e1 2a 42 c8 27 44 a6 f6 57 e7 d1 28
    1a 66 e0 de b0 8a d3 63 9f d2 38 4d 81 c2 04 37 d6 cc b2 c4 bd cc ff 60 a4 f6 b9 eb bd 4d cf e2 64 45 57 88 66 b6 2b e9 bd 31 e1 31 86 70 af 27 ce 44 0a e9 57 97 a7 16 78 62 5c 18 f7 61 12 d9
    91 a4 50 c0 f1 30 d5 ad 78 af 33 ec aa 07 9b b2 ad 6a 3b 23 da 17 82 6e 93 4b f6 00 11 58 92 6d 27 4d f0 3a 72 0d 24 90 de 35 ef ba bd 8b 71 10 1f c2 43 de ea 03 0b ce ba 2d 7b 78 0f 2d 1b ff
    7b a9 4e 7a fd 0a fe ac ce 03 c3 3c 3b bb de e0 b9 0b 40 4d e4 37 06 69 3c b3 b2 6c 76 27 4f 4c e7 5a d4 3e e5 3d 66 59 2c f1 9d 35 b1 4a bb 31 31 a2 74 f1 d8 42 19 88 46 4b f1 6a a7 29 b4 c0
    40 66 92 87 43 33 70 67 44 47 27 19 a8 67 98 d5 f7 69 d6 2f d1 fb 20 b2 08 0e a0 46 91 59 52 c4 d7 95 9a 32 ca 0a b4 89 b8 fe a1 78 7e 91 f3 6a 1e d2 53 e4 20 dc e8 de 18 8d 90 0e 41 97 d9 4a
    3a c8 5e 16 2a 36 00 74 71 5c 8c 87 f4 3d d4 63 01 67 ee 0e c0 4e 36 b0 b9 12 69 81 bc ad 1e 62 e4 ff 07 37 da ac d9 cb b7 25 b1 af f4 3f 13 23 88 f4 76 5c 7b 29 eb 6c b5 19 54 1b e1 b7 85 61
    f6 18 1a a3 e0 20 58 82 6f a2 65 de 12 10 b7 ef 0f 29 b5 52 6d f6 c3 98 fc 2d 42 79 06 d9 34 4b c3 c6 6f ed 66 e7 03 a4 73 07 21 83 60 62 44 fa fe 56 34 4b 1a ab 53 36 37 9a 08 af 09 d4 8e 19
    45 e9 eb 10 fe 2f 0f 61 52 eb 0d 26 e4 4a 05 8e 88 a5 d2 bf 23 b4 c3 9a 55 c0 b5 e3 f1 2e 58 8d c4 de 80 61 3b c2 31 44 ba f4 c0 e0 f2 9c d9 cd e2 78 14 ec b8 53 bd 4d e1 ef 76 e7 66 41 cf 99
    51 e1 16 11 2a 3a 9b ea b8 1d e8 0e 2d cb 71 be 53 a0 d0 c3 c5 75 50 39 4f 37 d0 ce bf 7f 94 46 36 89 fc 90 ad 28 15 97 71 3f 28 a1 ba 7f ad 44 4e 36 61 97 8a b5 6c ad 39 f6 79 80 63 dc f5 33
    ff fe fd 16 21 89 88 23 83 cf 0d 1f f4 0c 4e 51 4b c9 21 23 9f be 66 42 1f fd 26 15 5d ec eb dc 3f 38 0f df d7 66 e1 07 ba 03 d5 5b 02 cc f6 d0 b1 bf 6e cb 35 d1 11 6f 2e 19 a0 6a ae ca 38 87
    2f 12 f0 a0 26 17 3c b3 b4 fb 72 98 80 07 e4 96 3e ff 8c 1d 0d 8f e9 a0 8c 38 5b df a4 5a 8d 02 90 ee cc 4a c2 c4 53 3c c2 14 62 4c e8 ab aa be 76 66 4f d6 fd 66 eb 00 47 3d 82 8d 51 96 a3 18
    2a d6 b7 13 15 83 59 49 10 93 93 22 44 83 5e 71 7f 02 4a 82 d1 ae 91 1f db 65 50 2b 61 dd 1e d7 52 16 3d 92 19 ca d2 ad 11 73 70 fe 18 18 da a6 a9 e2 be b7 a9 04 7c 73 9c f7 9f 2c 00 b4 a4 cf
    a6 3e 8b 6f 15 1f 24 d6 00 f2 b3 6e 34 f3 1c 41 62 94 84 e6 ad 50 b9 42 a4 7d 3f 58 4b a4 9b 04 be 24 28 37 ce 11 e4 9b 3b 8f 56 f9 a9 0f d5 dd 09 1d 04 88 f4 6e de 39 e8 f3 79 4c 9d 4a 07 38
    58 15 77 9e 08 f7 43 78 f6 41 9b cb a4 af bc f9 a8 0a 22 b6 a0 bd f6 f6 5f 91 f0 da f7 12 95 e5 0b c3 a1 d6 72 12 d9 be 84 6b 60 b3 2a 97 e5 d0 fe 13 25 34 6a 90 7d 0a 0f cd 15 96 3c d8 1d 36
    3a ff 55 33 ba e4 43 46 f9 37 ad b6 5a 69 54 f3 21 d8 55 42 5c 82 86 ea 5e 66 b5 74 f8 66 53 86 83 6f 6d 3a d6 97 36 6e e2 98 ea 0b 4d d9 48 f8 55 51 3a f1 82 83 a9 42 ae 2c ea e3 16 44 6d f4
    95 53 31 80 69 83 e9 6c d0 30 a4 d6 f2 14 5c 6a 33 4d 6d 02 88 e1 4b 8d dd 46 7c b6 ea f8 4a 97 43 10 0a e1 24 67 d3 61 d3 2b 29 16 16 c4 f9 21 c0 69 b4 81 16 56 71 7f 7e 38 db c5 a9 e1 9e 4b
    aa 51 de 4e fb b7 65 3a 26 63 cb bc 74 cb 76 d2 a3 d4 ac 84 c5 c9 bb 51 a7 b6 cc af 0a 2e 50 da cc a7 35 ff 02 e4 ce 41 61 11 ff fc a3 f8 18 0d b8 2a 57 47 b2 41 35 99 b6 f5 d8 2e e5 ce 3a 1f
    89 de e2 7a c1 75 a1 df a5 bb 05 4f 36 0b dd 80 9d 5c 2b c0 89 f4 99 0c 1f 8c c2 1e 94 90 bc e3 63 16 1c 7a 55 69 a0 44 bc be ad 75 21 38 84 46 91 cb d5 37 94 62 e6 fe 5b 3e 5c 6a 0c d7 64 2c
    c6 f9 06 f0 dc d5 2d 59 cc d4 3d 4c 9a a3 07 1d c7 e1 24 12 2b 03 2e af 6f 71 4e 34 50 fe 1f 70 a8 69 1d 46 88 d3 2b 18 41 94 d2 85 a8 65 0d 02 04 7c 6d 33 4c e4 e8 c5 72 18 3d 15 5c fa 9f 7a
    59 2a 77 9b 4b a1 17 a5 8c b7 07 e4 90 7e a8 f7 18 84 22 40 e0 e1 f4 31 af 33 a9 4e ee d9 09 d5 88 97 67 d9 42 30 d6 d0 e5 f7 e9 25 af d9 71 ff 8e 2e af 56 64 ce ae 25 70 6a ed 2c d7 88 d0 b8
    a6 c8 61 9f ec cd b3 91 e3 a1 a3 1c 9c ae 2a 6c 5b f8 c2 e9 2b 30 71 4f 03 0f 80 ae 3e 04 cd b5 c7 d8 1a a1 51 19 d1 85 1b 7e 02 e6 aa 00 a0 99 8b f4 57 79 31 44 f0 48 8b 24 77 a6 2a 32 df 31
    48 08 49 11 d4 20 8f 80 6f f3 df 4e 38 4f 91 a6 f9 a5 0e 22 3d 5d 17 50 51 21 b4 17 1c cc 95 46 40 00 57 88 6e b9 d2 8e 0b 50 23 05 86 5c 13 e2 16 e0 87 4a b3 c6 d9 53 32 f4 a4 f6 ea 72 47 53
    f2 8b a1 d0 4a e8 c8 41 b1 7e ff 35 58 13 eb 2f 9b 53 0e ff 54 27 5f cd 49 d5 ec 83 50 a7 21 c5 0f 47 1b 76 be b3 20 2b 38 9b 1a f2 6f bc 4d cd c1 0d 75 9e 88 a7 ff e2 57 ba b1 bf ac 55 e8 7c
    e2 c6 02 8e ca 86 36 1d b0 64 94 c0 11 f6 a5 96 fa 5e 2e bc bb c0 32 13 f5 48 33 d8 15 9a 37 75 dc 9d 27 5d 71 ea d2 a9 1c 62 ed a4 be ad 8d 39 e1 a3 ba a8 6c 59 63 e6 15 d0 4c 28 9e 86 6c 10
    c7 6b 81 eb 63 51 3b 34 7b 35 0d e1 38 e4 8a 47 ab 73 0f ad 8c 86 13 33 93 6a 9f 67 e7 f5 88 69 80 17 9c 63 6c 65 68 42 af df fc 75 81 fb 58 f4 83 a6 e6 eb 68 c9 ed 22 59 83 df 87 63 14 cf ba
    20 34 2b d9 3b 80 3d 97 24 79 e7 74 93 c3 3f f5 02 ed 90 2d 3b fe 13 34 55 94 7c 23 0e 00 4c db 0d d0 7d 9e ee 9e eb 33 66 8c 72 c7 a0 a1 69 15 34 07 7a 52 6d 2f 5e 5a 53 24 61 62 aa 26 8b 8a
    5f 16 6f f4 9d 93 b0 9d 3f 55 fb 39 79 7f 7b 7e 76 dd d2 26 51 7e 9f d8 a7 6a 6b 29 7c ff 8a 22 ff b6 95 86 95 ee c9 70 aa 5a 5b ea 4e 1d 22 af 36 52 47 4f d4 52 32 54 6c 2c 37 de a6 00 3c 8b
    35 cc 9b c7 ef f3 51 bb f1 f1 42 1b c7 f2 7b 69 a1 26 53 f9 50 bc f9 f1 fa 96 ea b0 52 78 c3 71 92 f5 33 22 b7 b2 49 0b 3b 1b 34 dd 0f 43 49 5d e6 5e 36 d3 fc ad 46 aa 26 d4 90 e9 c6 9c 87 97
    4b 33 eb 22 97 2b 5a 11 85 87 81 fe 04 66 43 a5 5a cb 3d 74 e8 8a 49 c6 a5 8a 06 57 87 ce 65 88 7a 74 85 ce ae 3f 58 09 13 d4 72 ff 59 16 8c d6 63 1c 41 7d 39 41 18 22 93 c5 d1 1a ad 91 ad a0
    ac 70 ba 36 2e 01 33 3d 2c f9 e8 b1 9d 92 23 db 55 f7 99 e3 8a 1d 8c fc c7 ff 0f fb ea 8c e3 94 f6 8b c9 ab f1 e1 0e 5c 1c f8 3b 0a 2d 4e 59 d7 78 69 ca 48 48 7e 6d 0a c3 66 4d 5d df 9a a8 a8
    94 3c d9 d1 e0 23 14 03 47 77 0d 8b 06 d8 f7 40 39 72 cc b8 4b f2 b0 bc 30 e0 62 c7 73 a9 16 17 b7 d5 05 fd d2 c0 85 18 79 4c 4e 05 26 9a b9 ab 91 3a ba c5 0e 23 75 dd d6 3a e0 17 09 8e e6 ff
    2b bc 58 5d e5 85 d0 8a e3 b9 e8 d1 7b d0 31 c7 4f db db 8c 2d 02 fc 9d ea d2 73 1b 90 1f d7 1f 52 c1 16 22 c2 d6 0b cb 95 cf 6e 9f b9 d4 5f 14 20 c0 a4 47 5d e0 12 71 79 cb 1c bf df d8 26 e2
    c3 57 58 ef 7b f9 08 3a b8 2a 0b f5 6a 2d 62 78 21 1b a3 e7 a6 92 2a a1 b8 93 1c 4e 1b 84 49 40 ef e3 47 01 44 83 a5 73 4b 47 7f 03 c1 31 cc 2b bc e7 f0 1c 3f 92 f0 41 ab b7 87 75 e5 46 d7 67
    79 53 1e a2 6a d0 0f 63 1f 76 1b 83 e8 a5 5e c9 e9 af 8c e7 24 ed 40 ec 09 4f a3 2b 46 35 ef b5 14 40 b3 7f 67 96 a4 aa e6 a4 ea 7e d9 78 5a 89 84 c2 a8 9c 40 91 c6 04 79 87 41 29 14 c2 ea 9a
    cf 50 04 d4 28 1a 08 32 bf c6 42 5e 65 5c 6d e2 3f c8 0c 1b d7 3f 7b 77 22 ca ee 2d 54 12 08 88 e4 87 a2 e9 a2 4b 00 40 f5 d8 b9 69 6f d7 91 8c b2 c0 ac be 72 20 9c 73 70 0f e8 2d 81 66 4a f5
    b5 b6 4b 67 4c 1c b9 ed 23 74 63 4a 84 68 a9 53 dc b9 2d 8e 44 7a 43 82 93 b4 e6 0d a3 32 d8 e6 be b7 69 08 dd f7 41 9b f8 7e 92 30 b4 cd a7 61 bd 7a 3c ac b7 17 ac 14 63 e6 43 e7 bb 43 0f 34
    17 cd 8b e6 16 39 0c aa ad 33 66 5f c1 61 b5 7e e2 91 cf d6 f3 fe fc 4d e6 d8 f0 10 0b ca c5 6a 73 3b ce 7d 15 9d 65 73 8f 9c e2 57 cd 2d d4 76 40 79 24 77 35 8c 71 22 5f 08 7b fd d2 e9 68 1f
    cd 81 81 56 fd f7 82 39 04 e8 8f 53 b1 bb 1e fa 93 bc ca 83 f0 f1 9c e0 60 d4 11 21 95 40 01 d7 81 78 db 69 2d 31 ea 46 b7 7a d5 a0 2d 72 a7 f4 a5 7e 6c ed c9 ea 90 97 cc 48 6d f9 8f ff 84 31
    5e 24 a9 36 40 5c 2d 3f 4c 1e db ef f1 35 f1 72 3d ce 49 8b ff d4 09 32 5d 29 1a 99 20 8e 57 bb 95 53 35 e4 80 a5 0d a9 77 4a b1 14 8c 69 79 cc e8 8f 03 d6 21 7c e3 53 87 6e f0 9a d0 86 d5 b4
    30 84 f5 c9 32 2f 73 be ba cd 16 0f e3 7c d2 ba 48 69 dd fe 6d 43 81 c2 a1 04 cb c9 19 07 4f 6c 04 b3 da 6f 1a e5 ce 9b 3d 12 6e 93 68 44 6a 52 a6 f5 ce fe cf 5b dc 47 bb af e9 a3 a0 cc 3b be
    3d 70 37 5d 77 af f3 77 4d ca bb 2c 9f f9 ee 59 4c 5e b9 40 8c d5 ee b1 63 53 a7 e0 a3 d0 f1 ec e3 11 c2 71 b3 e7 f1 f1 dc 62 82 cc a7 c6 61 d0 e0 4d 99 49 35 ab 6a d3 2c 08 51 be f5 44 17 8e
    1b 08 2f 60 8b 8a 9c 51 ec 11 b0 05 28 55 a4 ec 4a 54 9d ff 3c 86 fa 94 44 bc 2b 71 20 a5 09 29 ea 27 e1 53 51 e0 1f e6 c3 08 48 33 36 eb 63 f5 0a 55 4b 94 99 a3 f1 6f 00 95 e1 ac df 33 90 b3
    62 d7 e9 03 55 75 ba 85 d2 5b 5c cf 9e 0b f0 b7 61 33 2a ef f8 c8 bd cc 0d a5 89 9a e5 75 ab 3e af 3c ed 86 46 ce 33 d5 c3 bf c8 b5 04 1e 48 09 00 88 e6 c3 ea 9a e7 cc 9a b9 5f 46 bd e0 d6 d8
    88 b9 d4 26 04 a1 b7 4d 0e 9d ec 27 65 8b 6a 81 b5 8e 29 12 5f db 12 81 99 13 d1 1e 61 ec 77 ff 32 96 20 1e ec 27 1c d4 2d ae 99 21 88 3b 7c e1 b8 ee 37 15 bf 58 35 ee 51 8b 1d d4 aa 82 fd db
    84 6d a1 5d 41 54 eb 3f 3f df db 89 06 5d 5e 83 4b d1 f8 67 6f fa ec d8 38 65 51 61 5d 53 c3 e2 54 63 6e 5f a2 fe 56 4a a1 e0 a5 10 d0 98 41 0d 51 82 cb ff 75 d0 b5 75 97 2c 43 bd 19 e3 d8 3a
    61 95 d9 d0 f7 d5 ee 18 6b 3b 90 b2 da dc 94 da 2b e1 97 b8 cd 0d c3 85 9e 24 17 d9 9c 70 b0 c7 b7 58 cd 2f 9f f7 ae 8a 4e ac 9d 98 9f 98 91 c2 f3 ea 9a 3d ab 7a 89 17 47 cb 71 0e 20 fb 94 af
    cb 17 ba b6 d2 4c e3 0e 95 ae c5 b5 b3 e2 5d 6d 27 7c b8 f4 4e c0 3d eb 3f 60 57 99 c0 66 61 66 ed 25 19 a0 d8 c7 c7 11 d7 81 91 05 b8 c0 16 bd 24 2f 60 93 7b 27 76 63 b3 85 af b6 d3 ef c8 38
    a5 05 a0 f8 e1 3d f7 fe fb 0b 29 c7 48 07 48 f0 e2 3f 2e f7 2c f4 1c 95 4c 14 81 67 bf 14 cc cc c3 01 8b fd 4e e7 49 73 f4 ee 00 98 b7 4e 8b 15 c4 c4 6a 3e 8a 69 ba a0 97 79 36 c9 31 ab 45 d2
    22 5e 85 e5 aa c8 4d 53 f4 6d 0f da f8 1d 81 80 01 09 de 6d 9d 7f 83 54 6c 48 f7 d9 26 a6 b5 24 4c d7 be cb 91 58 b0 06 05 8a a7 dc 02 8e 2d 59 2a 31 de 4a 83 1a 5a b2 ac 22 c1 14 fe b0 04 17
    39 7e 09 4c 76 0d 23 60 48 3a 52 9d f6 e3 ee 01 a8 10 2a b6 8f 41 5f 54 21 9f c4 f2 8c 09 c1 d4 20 f9 0b 79 55 c0 88 98 09 8d db 61 b6 ba c0 29 c6 66 bc ab f9 09 04 f8 7d 9e 39 3a 6a 61 32 6e
    a7 d8 60 37 3a 1b cd 43 d2 90 b3 3d e4 04 3a d6 0b 9a c9 0e 99 86 69 e7 15 3f 3d ee 4d b6 e3 d7 cb 68 5f 9f 73 01 38 7b c3 1f bb f8 e3 16 2a 94 27 30 c7 a9 a7 d3 b9 84 76 03 38 9e 93 28 39 6b
    78 d0 25 24 86 14 19 55 88 bb db ce d0 76 85 19 50 92 9f 40 5c f4 28 f3 06 da f5 62 7e 8c 20 23 bd 9d be 4f 10 ab 82 63 a8 7b 92 3f 49 a5 72 33 5f 70 6a 0f 34 f0 d1 2d 4d 9c d9 4f 74 7b 00 a4
    19 f7 f1 a8 e9 51 bf 2c c8 d5 73 be 26 8e 0b 5c f6 2f 80 59 57 d6 13 18 5b 5b 94 17 40 e1 be 24 55 0d 4a e9 be cd 01 b5 f4 9c 5a e1 e6 dc ce c8 5f 79 db 8a e0 88 00 d5 27 0d 83 4d ee de b4 14
    a9 a6 bd a9 3a 8c 4d 61 cd 58 3f 3c e2 7a 8c d8 7f bf a7 ac 02 22 63 26 5c 10 7c ed 93 b5 00 df f9 b8 e1 0d 2e 1b d3 fd ae 27

        TLS-зашифрованный пакет с изображением
        Header
          17 - type is 0x17 (application data)
          03 03 - protocol version is "3,3" (TLS 1.2)
          1e 25  - длина последующего с контрольной суммой сообщения в BE-notation (7717)
        Encryption IV ?
        остаток 7717 байт:
        00 00 00 00 00 00 00 01 89 42 81 ...  
        после дешифрации - 7693 байт (см далее)

вариант 2 - TLS не активен:

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 20 05 d2
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        20    - cmd 
        05    - cfg flag 0x5
        d2    - контрольная сумма

read
    C0 0D 1E EB
        С0    - флаг ???
        0D 1E - полная длина следующего пакета в LE-notation (76923)
        EB    - контрольная сумма

    20 0A 1E 00 00 00 00 00 06 10 D8 61 72 B6 37 9C FB 7B 7E B7 87 FF 37 86 80 78 48 90 7C 84 86 78 B8 9C 08 8E 92 B9 F8 EC 58 92 95 79 09 90 6F 96 99 B9 09 84 88 9A 93 B9 09 7C 98 96 9A C9 C9 3B
    F3 97 9B 49 49 A8 B3 99 9A C9 79 B0 EC 9B 9C 49 09 DB BF 9B 95 89 C9 7F 88 9A 9C 09 09 CC B0 9A 98 09 49 14 EF 86 7E C7 F7 30 40 72 8B B8 48 AF 58 8E 93 B9 89 6C 8F 9A 94 79 49 CF E7 99 9D C9
    79 F4 0C A4 A4 BA 7A 48 88 A8 A7 7A CA 84 7C A9 A6 3A 0A CB 9B A8 A9 CA 7A D4 AF AC AD 0A 4A AB 30 AA AE FB 7A A7 9C AB A8 7A 7A CF CF AF AA 4A BA C3 BF AD AB 4A 3A B0 E0 AD AD CA 0A B4 EC AC
    A7 8A 4A 3F FF 9D 90 38 08 20 EC 82 93 78 C9 60 1B 9B 9F 4A 3A 1B 38 A6 A6 BA FA 78 DC A8 AA CA 0A BB 23 AF B3 FB 4B 03 5F B3 B3 8B 8B AC 34 B7 B5 8B 7B 6C 87 BA B6 BB FB 88 63 BB BB 8B 0B 6F
    0B BC BF 3C 4B 98 88 BC BD 3B BB E8 67 BC BB FB 3B A3 EB BB B9 7B BB C3 8B BE BD 7B FB DC BF B6 BA 3B 4B 00 DB A7 9D C9 F8 3F 4C 83 9A 39 49 E4 44 A1 A7 4A BA A3 AB AB AE FA FB 33 37 B0 B2 7B
    FB 58 7C B4 BB FB 0B BB CC B9 BB 4B 3B F4 CC C0 BC BB 7B BB 23 BF BE BC 7C 0C 17 C0 C1 CC 8B CC 7F C2 BF FC FB FB E4 BF C0 BB 7B F3 4F BF C2 3C 8C 4C 33 C3 BE CC 0C 38 08 C4 C3 BC BC 30 1B C0
    BD 0C 8B 6C 4B B5 A4 CA 87 F4 BF 7F 93 08 F9 BC 1F A0 A3 CA 7A 18 2B AB A9 7A 7A E4 18 A9 B0 8B 8B 03 4B B3 B9 8B CB 7F AF B2 BB 0B 4B 67 E0 BE BF CB 8B E3 E8 C3 C2 4B 8B E3 F7 BA BF BB FC 37
    2F C1 C8 4C BC 53 53 BF BF 7C FC 2B 3C C6 C6 3C 4C 50 5B C1 C6 8C FC A4 F4 C8 C2 3B 4C 7F 2C C4 BE 4C 0B C3 17 B2 A1 8A F7 DB A3 7D 94 38 C9 9C 13 9A 9D 0A 49 FC 1C A4 A8 3A 0A A0 F4 A8 AC 3A
    7A 8C 1F B3 B2 4B 4B 58 28 AF B6 BB 4B 2F 58 B7 BD CB 4B 98 A3 BE BC BB 0B A0 D3 B7 BC FB 4B 7F 7F BC BB 4B 7B E0 07 BC BD 8C 3B 9F CF BE BD 0B BB E0 EB BC C1 3B 4B D7 8B C2 B9 BB FC 08 8F BE
    B7 8B 3B 43 9B AE 99 C9 48 44 C4 84 97 88 F9 A0 2C 9F A4 4A BA 68 67 AB A9 7A 8A CB DB A8 AE 3A 3A F8 58 B7 B6 FB 3B 7B 9C B4 B7 BB BB 18 AC B9 BF CB 7B E7 B3 BF BC 3B FB EC F0 B9 C0 4B FB FB
    D3 C0 C2 8B 4C 13 3B BE C1 0C BB F0 23 C3 C4 3C 3C 34 28 C1 C0 BC 8C 67 D7 C3 BC BB BC 40 E3 BF BE 3B BB 9C 0F AD A0 FA 07 DC C7 7E 97 B8 39 F4 30 9E A5 7A F9 F3 3B AB A9 8A 3A AB 1F AB AE 0B
    0A EB 6B B6 B5 FB 7B 8B 87 B1 B7 3B 0B 87 8C BB C0 3B 0B C3 B3 BD C0 8B 4B F7 C3 BA C2 CB FB E3 18 BD C1 3C 4C 23 0B BE BF FC FB E3 17 C3 C1 FC 7C 3F 28 C3 C2 FC 3C 2B E0 C5 C1 3B CC 5B 1F BC
    BA 0C FB A8 10 AE A1 3A 87 E4 B3 7E 93 08 C9 D0 DB 9B A2 09 4A 1C 34 A4 A6 FA 8A 70 A0 A6 AC 3A 8A C7 07 B3 B4 FB 0B 33 4B B4 B3 4B 8B 47 A7 B7 BA BB BB A8 03 BA BC BC 8C 0F BB BA BC 4B 3B DF
    98 C1 B9 BB 0B DC EB BE BD CB FB AF AB BF BB BB 7B F4 FF B8 BA 4B BB C8 CF BD BF FB 3B E3 DF BC B9 FB 7B 50 7C AC 98 09 87 E7 C0 7E 8F B8 89 B8 EF 9B A1 C9 4A 17 3F A7 A2 8A FA 64 C4 A2 AA 8A
    0A D0 DC B0 B3 8A CB 10 37 B3 B0 BB FB 43 A0 B5 B7 BB 0B 7F 9B BA B5 4B 3B AC 5B B6 BB BB 4B 87 87 BC B8 0B 3B BB C8 B8 BA 0B FB 9C 7B BB B8 FB 8B DB D4 B6 B8 FB 4B 8F 78 B7 BB 7B FB A7 97 B8
    B7 3B 3B 24 84 A9 98 B9 F8 4B F4 84 97 B8 09 DC DF 9D A3 C9 4A 07 43 A8 A5 BA 0A 7F CC A6 AD 8A 3A D3 CC B6 B3 4A 4B 50 94 B2 B3 BB 7B 64 84 B5 BC 0B 4B 8B D7 B7 B9 7B 3B CB C8 BA BF BB 0B B4
    90 C0 BD FB 3B EF D7 BC BE 3B FC 10 C0 BA BC FB 4C 23 FB BC BA FB FB E0 A3 BC BF 7B 0B BB AC B9 BF FB 8B 28 C4 A7 9C 79 88 07 0B 80 98 39 C9 A8 CF A0 A1 B9 4A 50 44 A7 A2 8A CA BB AC A5 AE 4A
    CA EB EF B2 B2 3A FB 40 7B B6 B1 0B FB 4C B8 B8 B6 FB CB 97 D0 BA BB 7B 4B B4 87 BB BD 0B 3B A7 A0 BE B7 7B 8B E0 B8 BD BC BB 4B E7 B8 BF BD 3B BB E8 E4 BC BF 3B 0B CC BC BF BE 7B 4B B4 D3 BD
    B7 CB CB 00 A4 AA 9A 89 F7 AC D3 7A 90 38 39 CF 0C 9A A3 3A BA 2B 3C A4 A8 0A CA 8F AF A8 AA 0A 7A C8 C7 AE B5 CA BB 3F 5B B4 B6 8B 4B 67 9B BB B6 3B FB 9B 7B B6 B5 FB FB F3 AF BE B6 8B CB 98
    F7 BC BD 7B 7B CC EB BE BF 3B BB AF B8 C1 BB BB CB B8 23 C0 C0 8C 4B EF AC C0 BE 7B 7B A4 97 BA BA FB 8B 0F AB AC 9A C9 B7 C8 B8 7C 94 88 89 98 1F 98 9F 7A 8A 3F EF A1 A3 B9 BA 43 80 A7 A9 0A
    4A 87 7F B2 B0 8A 4B 1B 43 AC B3 BB BB 1C 40 B7 B1 FB 7B 63 53 B1 B4 CB CB A0 53 B8 B5 4B 7B 87 AC B9 B4 8B CB 5F 64 B7 BA 8B 8B 3C 67 B9 B6 3B 8B 90 84 BA BD FB 3B 8C 77 BA B9 0B FB 40 6B B4
    B5 FB FA E7 74 A6 97 79 47 A3 A7 7A 90 B8 B9 A4 EF 9D A4 B9 4A 2C 38 A3 A2 8A 4A 78 60 AB A9 7A BA B8 90 B3 B3 8A CB 64 63 B3 B1 3B CB 2F AF B6 B5 BB 4B 8C 93 B4 B8 FB 8B D7 74 BA B4 3B 0B 97
    B0 BC BD 8B 8B 9F AC BB BB FB 8B 98 4F BB BA 4B FB DB D7 BE BE BB 8B AF 9F BE BC 4B 4B 93 88 B9 BB 4B BA FC B8 AA 9B 89 77 B3 FC 7B 98 88 39 B3 1B 9C A3 BA 4A 70 1C A9 A5 7A 3A A0 A4 A9 AB 4A
    8A FF 0F B4 B3 FB 4B 84 88 B4 B1 7B 7B 88 74 BB B8 BB 0B 8F B8 BA BA BB 0C 18 9B BC B8 BB BB 8B F7 BD BD 7B BB D4 B3 BB BF 3B BB DC C3 BE BC FB 8B E0 F4 BD BD 7B FB E4 D7 BD BD 4B BB A0 94 BA
    BB FB 0B 24 83 AA 98 89 87 74 C7 77 93 C8 79 8F A8 9D A0 C9 89 D8 B7 A3 A3 F9 BA 9B A7 A3 AB 3A 4A 80 AF AD B0 8A FA CC 24 B2 AF BB 8B 77 9C B6 B6 0B 4B 64 B0 B5 B3 3B 4B 7F 6B B5 B8 3B BB 34
    8F B6 BC 3B 7B 6F B3 B8 B8 FB FB B7 63 B6 BB 7B BB AF B7 B8 B9 CB 3B A3 9F BB BA BB 7B 6B 83 B4 B3 4B CA CC 8F AC 99 39 C7 A8 C3 7A 93 B8 B9 A7 D4 9E 9B 49 79 F3 07 A5 A1 0A 8A 8F B8 A1 AA CA
    BA 8F A3 AA B1 CA 8A BF EB AF AF 0A CB 5B 33 B0 B7 CB 4B 28 7C B6 B3 7B BB 4C 90 B6 B4 BB 8B 4C 37 B9 B6 BB 0B A0 5C B6 B7 4B BB 98 7B B6 B6 0B FB 6B 6B B8 B9 3B CB 24 4F B2 B9 CB 4B 14 84 B0
    B0 7B 4A CC 37 A6 93 B9 48 00 BB 80 95 88 C9 C4 EB A0 A1 F9 49 F7 10 A6 A3 FA 4A 64 BB A6 AD 3A FA E3 D7 AC B5 CA 4B 3F 64 B2 B4 3B CB BC 8C B4 B8 7B 3B 88 C8 B7 B2 4B 8B 64 94 B7 BA 0B FB 27
    B3 BB BA BB 0B AF C8 BA BA FB 0B CC 54 BA B9 FB 3B BB D3 BB B8 FB BB C7 9B B8 BC 7B 7B 67 93 B1 B0 FB 3A CC A4 AC 9A 49 37 BF EC 7C 96 F8 C9 E0 10 A0 9F CA 0A 14 24 A6 A6 4A BA 9F CF AA AD CA
    4A DC E4 AF B6 7A 3B 08 3F B4 B2 8B 4B 73 B4 B6 B8 FB 8B 57 93 B8 BC 7B 3B 90 8C B8 BA 7B 3B 8F DB BC B9 CB 7B A7 C3 B9 B7 7B 4B C3 AC B9 BA BB 8B C3 C3 B8 BA 3B 7B 9F AC BB BA 8B 3B 5B 9C B3
    B4 8B CB 14 7B A9 97 B9 F7 9F 6B 79 91 38 89 78 9F 99 9C 89 89 C8 FF 9F A1 89 4A 48 73 A0 AA FA 7A 68 90 AC B1 8A 0B 3C 54 B4 B3 BB 8B 67 2B B9 BC CB BB 44 6F B7 B8 7B 3B A4 5F B7 BA BB 4B 7F
    94 BC BB 4B 0B 73 AB B8 BB BB CB B4 50 BC BA CB BB E3 EB B9 B9 7B 0B 87 87 BA B9 CB 0B 7B 8C BB B4 FB 3A FC 5C A6 96 09 77 A8 64 7A 93 38 89 60 AC 9E 9D 39 F9 D7 23 A0 A2 0A 0A 2C 7C A4 A8 CA
    7A 78 6B A8 AF 0A 4B 00 4C B1 AD CB FB 24 34 B4 B8 4B 4B 3B 6B B9 B8 BB BB 88 F4 B5 B8 4A 7B 38 1F B8 B7 8B 0B 4B 64 B1 B8 3B 3B A7 0C BD B9 BB 4B 93 B4 B5 B5 4B CB 78 50 B5 B5 BB BB 57 4C B3
    B1 BB 4A F8 50 A4 95 49 77 B4 B4 7B 95 78 79 9C C8 9C 9D 79 C9 D0 64 A2 A4 BA BA 67 93 A3 AC BA CA AF 98 AB B0 0A BB 13 50 B6 B0 FB 4B 83 5C B5 BE 8B 3B 77 83 B8 B7 8B 3B 83 47 BA BA FB 0B 83
    9F BD BA 0B 8B 8B B7 B4 BD BB BB B4 4C BC BA BB CB B4 E8 BC B7 FB 0B 9F 5B B9 B8 CB 0B 8F 8C BC B3 7B BA EF 6C A8 97 09 37 A3 E7 7A 96 B8 09 C8 EB 9E 9F C9 49 C3 24 A6 A6 FA BA 9C 88 A4 AE CA
    FA A4 8F AA B1 FA FB 23 5B B7 B3 4B 8B 9C 7C B8 B9 3B 7B 6F C3 B8 BB 7B 8B B4 5F B7 BB 4B FB AC CF BD BC 0B 4B 77 CC B9 BB BB 7B 8C A3 BB BA 0B 7B B4 DC B7 BA CB FB 97 C0 BB B7 3B BB 90 AC B8
    B1 4B BB 0C 5F A8 96 49 47 94 C7 79 8E 48 79 88 D7 9B 9D 39 0A 3F E7 A0 9D B9 BA 48 73 A4 A7 0A BA D3 AC AB B3 BA BA EB 63 AD B1 3B 4B 87 64 B2 B6 0B 3B 67 23 B4 B4 FB FB A3 48 B6 BB 3B 3B 40
    93 BB B8 BB BB 98 8B B7 B8 0B 4B 74 60 BA BB 7B FB 74 EC BA BC 4B 8B B4 68 BB B7 4B 3B 6B 0C B7 B2 4B CA E3 14 A5 91 79 37 73 B7 77 94 48 F9 83 94 99 9D 49 49 E3 C7 A0 9E F9 BA 43 84 A5 A6 4A
    BA B7 EF AA B4 CA 4A CF 37 AC AC 8B 4B 3C 27 B4 B5 7B 7B 63 6B B2 B1 BB CB 5B 57 B4 B4 FB 3B 3F 4C B6 B6 7B BB 57 7F B7 B2 0B 3B 24 50 B6 B8 3B BB 78 77 B7 B6 8B FB 7F 4B B8 B6 8B CB 34 F4 AD
    AF CA BA A3 F8 A0 8F C8 C7 AB C4 7A 91 F8 09 B4 F3 9E 9B B9 79 DC E4 A2 A0 C9 CA 37 BF A5 A9 8A 7A A7 D0 AC B3 8A 8A E0 7C B1 B2 8B 7B 73 1F B0 B9 4B 4B 5F A0 B4 B6 4B 7B AF CB B9 B8 CB 4B 60
    44 BA B9 3B FB 93 9C B9 B8 BB BB 67 3F B7 B6 BB 3B 94 BF BB BA CB 7B 93 98 BB B7 BB 4B C0 27 B3 B2 FB 3A CF 67 A7 96 B9 F7 7C 14 77 94 F9 B9 5F E7 A1 9E 79 4A 24 0C A1 A3 CA 3A 7C 8C A6 AA BA
    3A B4 EB AE B0 7A 7B 3C 88 B2 B4 3B BB 73 47 B5 B9 FB CB 3B 44 B5 B7 CB FB C4 63 BA BC 8B CB 38 77 BB BB CB BB 94 B0 B7 B6 8B 8B 73 83 B6 B6 7B FB AC 90 B8 BC 3B FB A7 8C BC BB CB 3B 7B 28 B2
    B2 CB 8A C3 43 A6 94 79 B7 BB A4 7B 93 C8 89 98 A8 9B 9D 89 8A 3C 14 9E A3 7A BA 3C D7 A7 AA 4A 7A 83 7F AE AD BA 0A E0 2F B0 B1 FB 7A FF 8B B8 BC 3B 0B 27 60 B4 B4 4B CB 74 5B B4 B8 7B 4B B3
    6B B9 B9 7B 4B A8 83 BA BA CB 8B 93 84 BE B9 CB 7B DF 7F B7 BB 7B FB 94 84 BB B8 7B 7B 5F 7B B3 B1 CB CA CB 6B A3 96 B9 C7 9C 7C 79 91 48 49 87 BF 96 9E C9 89 D4 33 9E 9E 8A 3A 4C A3 A3 A9 FA
    7A 94 87 AC AF 7A BA CF 38 AF AE BB BA EC 18 B4 B1 3B 7B 5B 6F B4 B0 FB BB 8B E8 B4 B6 0A CB 7B 77 B5 B3 BB 0B 1C 88 B3 B4 8B 7B 64 70 B9 B1 CB FB 9F A4 B9 B9 FB 4B 20 6B B5 B6 8B 3B 27 4C AF
    B1 3B CA 94 13 A2 91 49 37 B3 48 7B 8E 78 C9 8F 74 99 9C B9 8A 0B 64 A2 A4 CA 7A 57 9C A6 AD 4A 4A 7C B7 AD B2 3A 4B 0B 3C AF B2 BB FB 00 44 B6 B5 7B 0B 73 43 B7 B3 3B 0B BB 63 B7 B6 FB CB 54
    8C B4 B7 BB 7B 8B 83 B8 B8 0B BB 7F 6F BB B7 0B 7B CB 87 B9 BB 4B FB 97 98 BA B7 CB FB 64 44 B3 B0 BB FA 88 60 A4 96 49 B7 BB D7 7B 93 38 B9 A3 C8 9A 9C C9 39 FB 6C A2 A5 8A 7A 8F 98 A8 A8 7A
    0A D3 AC AE B1 8A BB 0B 7B B4 B1 BB 7B 28 77 B9 BB 4B BB 94 7F B5 B7 FB 0C 04 84 B6 BB 3B 4B AC BB B7 B6 0B 7B C0 BB BB BB 3B 8B A0 8B BB B9 BB 3B AF 88 B8 BD 7B FB 64 84 BA BB 8B 4B 74 84 B4
    B4 7B 8A DB 68 A2 96 B9 F7 5F 5F 75 8D 78 39 3B A7 91 99 B9 F9 9B AB A1 9C 09 3A 6F 44 A3 A4 BA 8A 8B A8 B0 AA CA 0A CF E4 AF AE 8A 8B 00 43 B2 B8 FB BB 50 43 B6 B4 CB FB 84 47 B3 B5 7B 8B 90
    7B B6 B2 BB BB 78 9C B4 B5 8B 3B 9F 4C BE B6 7B 8B 97 4C B7 B6 FB 7B 08 43 B7 B7 CB 0B 53 2F B7 AD 4B 3A BC 00 9F 90 39 87 AB 9C 7A 93 48 89 73 D3 94 9D C9 39 CC A8 A2 9E 49 4A 70 38 A3 A7 4A
    3A A0 93 AC AB 4A 8A D3 F4 AB AC 7A 8A EC 17 B1 B4 8B 8B 4B 44 B8 B3 FB 3B 60 54 B2 B5 7B FB 50 4F B6 B2 7B 4B 47 74 B3 B5 4B 7B 68 14 B5 B6 8B BB 4F 68 B5 B4 0B 0B 33 2C B2 B4 7B 0B 67 50 AF
    AB CB 8A CF EC 9E 8F 08 77 E7 C3 7E 91 88 B9 7F 7F 97 9E 09 39 D3 FC A2 A5 09 CA 7B 6B A5 A6 4A 4A EC CB B0 B1 3A 0B 2F 20 B1 B4 FB 7B 3F 48 B6 B8 CB 3B 54 B0 BB B6 CB CB EC 7B B2 B5 CB FB B3
    4C B7 B4 BB 7B B3 A3 B6 B6 FB FB 87 5F BC BB 4B 4B C0 8B B9 B6 4B FB 6F 6C B5 B8 3B FB 93 60 B3 AE CB 4A DF 8F A4 98 F9 C7 AF BC 7A 90 48 C9 5F F8 98 9E 39 C9 D8 07 A5 A3 4A 7A A3 BB A6 A8 FA
    BA BB CB B0 B3 8A BB 33 4C AE B5 BB 3B 37 88 B5 BA CB 0B 60 84 BC BC BB CB 90 84 B7 B7 7B CB B7 9B B5 B7 8B 3B 7C B8 B2 B8 0B 3B BF A3 BD BB 3B 3B AB 93 B8 B6 CB CB 40 97 B7 BA 4B BB 78 74 B7
    AE FB 8A E8 68 A2 96 B9 B7 6C 7F 76 8E 88 89 4C 8B 96 9B 39 49 63 A0 A1 A3 F9 0A 33 84 9F A6 BA BA 64 77 AA AD BA BB 13 00 AD B3 8B 3B 68 1B B3 B1 0B BB 3C 6B B4 B4 7B CB 9F AB B5 B9 7B CB 50
    AB B6 B5 BB 7B DF 93 B4 BA 4B FB 38 B7 BA BB 3B 8B B0 B4 B6 B8 CB 0B 84 8F B8 B9 BB 8B 30 53 B0 B0 BB 3A D8 EC A1 8F 38 37 83 8F 78 8F 48 C9 28 8F 97 97 B9 89 C0 C3 9F A2 79 3A 34 78 9F A7 4A
    4A 80 63 A9 AC 0A 8A DF 3B A9 AF CB CB 3C FB B3 AF CA CB 33 28 B1 B0 3B FB 57 80 B5 B8 3B FB 1B 68 B5 B0 7B BB 84 58 B1 B9 0B FB 43 54 B6 B4 FB 0B 63 73 B6 B6 BB 0B 67 43 B8 B7 3B CB 38 34 AC
    AD FB BA D4 D4 A4 8D 88 77 B7 98 7B 90 38 C9 6C A7 96 9F B9 09 94 F7 A0 A4 39 0A 28 6F A3 A5 CA 0A C8 B3 AC AF 7A 7B 00 43 B0 B2 7B BB 54 3C B8 B2 4B BB 34 9B B2 B5 BB BB A3 93 B9 B7 7B 8B 3C
    B4 B6 B6 BB 8B AF 77 B2 B7 7B 8B 80 78 B9 B5 0B 7B C7 A3 B9 BA CB BB A3 84 BA BA 3B FB 77 6B B0 B1 FB 4A FC 0C A1 91 09 F7 A0 77 79 93 88 F9 7C 9F 96 A1 C9 49 E4 1C A5 A4 8A 3A 80 B7 A8 A9 8A
    FA A4 8C AD AE 7A 3A EB 9C B2 B5 BB 4B 80 47 B8 B8 FB CB 1F A8 B7 B4 4B 3B CF 9B B8 B7 FB 7B 57 C0 B9 B8 0B BB C0 AF B6 BC BB FB 58 D4 BA B6 7B 3B B7 A4 B9 BE BB 0B 9F 93 B8 BD 0B CB 77 74 B4
    B3 7B 3B 13 40 A4 94 79 B7 3C AF 73 8C F8 89 37 6B 91 9A C9 49 8F E0 9C 9D F9 FA 13 3B A4 AA 4A FA A4 A4 A8 AE CA BA EF 07 A9 B2 0B BB 2C 1C B5 B3 7B 8B 28 7F B2 B4 BB 4B 57 38 B7 B5 4B 8B 28
    77 B5 B4 8B 0B AB 6F B7 BA 0B CB 90 4B BB B7 FB FB BF 6F B5 B5 7B FB AB 17 B9 B9 CB 4B 77 57 B3 B2 0B 7A F3 5B A4 95 C9 B7 3F 73 73 8B 88 F9 6B B0 97 9D 79 B9 80 BC 9A 9F F9 3A 07 68 A7 A9 7A
    3A AB 7C A9 AE 0A 8A C8 23 AD B0 0B 7B 0F 30 B4 B4 BB 4B 24 74 B0 B1 FB 0B 2B 57 B8 B1 BB 0B 1C 54 B2 B5 8B 8B 58 43 B4 B4 FB 8B 33 73 B6 B7 7B FB 8C 63 B2 B3 8B 0B 5B 04 B7 B4 FB 0B 6C 3F AF
    AC 3B 7A EF 5F A4 96 09 07 83 8C 78 8B 08 F9 63 B4 97 99 89 79 B4 E4 9C A0 09 8A 53 7B A7 AC 8A 8A 98 A8 AB B1 3A FA E4 2B AD B3 BB FB 34 20 B6 B7 FB 8B 67 BC B1 B4 CB 7B 4F 6B B5 B6 BB CB 3F
    8B B6 BA 8B BB BF 70 B6 B5 CB 8B A8 77 BB B9 3B BB C7 98 B1 B9 0B FB 74 67 B7 BA FB FB 5B 68 AF B0 4B 0A F0 C0 A8 9C 39 07 D0 0B 7D 96 39 09 BF 08 9C 9E 0A BA 23 F7 A6 A5 F9 FA D4 94 A6 AF 3A
    CB 08 FB B1 B5 CA 8B 6F A3 B4 B3 FB BB 70 73 BA BA BB FB 7B DC B6 BA 4B 8B AB 70 BC B9 7B FB 6B C4 B8 BB BB 3C 03 B3 BD B9 FB 3B 9B 7B BE BA CB 8B CF 0C BC BE FC 0B 90 BB BC BB FB CB 98 C0 BB
    B5 7B BB 2F E3 AB 9E 79 C7 30 33 72 86 F8 B8 FF 5C 92 99 F9 F9 48 AC 98 99 C9 0A 0B E4 9F A6 79 FA 24 6C A8 A8 3A 4A 9C BF A8 AE CA 8A A0 18 B0 B0 BB 8B 0B DF AE AE BA 7B 24 9C AF B2 7A CB 23
    F3 B3 B3 FA FA E3 34 B0 B1 0B 8B 17 47 B3 AD CB FA FC 23 AC AF CB CB 0B 03 AF B0 4B 8B 17 FB AC A6 BA 0A 77 F4 9D 8F 48 77 48 5B 74 8D 78 79 3B 73 97 9B 39 89 7F 00 9D 9D 8A 3A 58 6B A0 A7 BA
    8A 6B 9B A7 AC 4A 3A 6F EC AA AD BA CA E4 2B AD B2 FB 4A F4 CF AF B1 4A 4B 0B BB AD B2 4A CB 04 0F B4 B2 7B 7B 08 33 B3 B5 7B CA F7 17 B5 AF BB 0A DB F7 AF B1 3A CA EF DF B1 AF BA 3B 0C E7 AC
    A7 CA 8A 50 FC 9E 90 08 B7 6C 94 76 8D 48 09 98 88 98 9C 89 89 CC 13 9F A1 8A 3A B7 2F A4 AD 3A CA 68 9C A9 AE 0A 8A E0 08 AE AF CB 4B 20 3F B3 B8 BB 8B 2C 24 B2 B6 0B 0B 3B CF B5 B5 BA BB 44
    34 B7 B4 CB FB 38 64 B7 B2 4B BB 2B 2F B1 B1 4B FB 20 1F B2 B4 0B 8B 20 23 B6 B3 CB 0B 4F 18 AB AE BB 7A 9B 17 A4 91 B9 F7 73 77 76 90 F8 C9 5F BB 95 9C C9 89 B0 E3 A2 A1 09 3A 80 3F A3 AA FA
    8A 8B 03 A9 AD 8B 4A F7 47 AE B0 8B BB 1B 5F B2 B7 BB BB 5F 3F B6 B6 BB FB 93 40 B6 B9 4B CB 5C 3B BB B6 3B FB 6B 7F B5 B4 8B BB 6B 4B B6 B0 FB FB 73 57 B1 B6 0B 8B 23 5C B9 B1 3B 7B 7B 53 B2
    AE 0B CA 93 0C A5 91 09 47 77 57 77 8E B8 09 38 8B 95 9D C9 09 BF C3 A2 9F B9 7A 1C 84 A0 A8 4A 0A A7 B0 AD AB FA 8A 74 23 AD AF 3B FB 17 38 B2 B4 FB 4B 50 20 B6 B3 FB BB 60 57 B1 B1 BB BB 74
    CF B5 B7 FB 3B 40 63 B6 B4 8B 4B 6B 80 B7 B5 0B FB 37 68 B9 B4 BB 8B 70 1C B6 B6 3B FB 3C FF B5 AE 3A 4A B4 54 A2 95 79 C7 4F 7B 74 91 48 49 4C E4 97 9D 89 F9 E8 A0 A2 9C 09 3A 57 58 A2 A2 0A
    7A DC 9B AC AB CA 7A 9C 17 AA AA 0B 8A D3 23 B0 AF FB 4B 03 F7 B3 B9 4A 0B 5B 27 B0 AE 7B CB 43 8B B3 B6 FB 3A EB 38 B1 B1 4B FB 34 34 B7 B3 3B 8B 78 8B B3 B2 3B CB 2F BF AE B4 8A CA FF 00 AE
    AF BB 4A AB 13 A2 91 89 87 B7 9B 7B 92 48 B9 3C 84 99 9F 49 79 E4 F7 A3 A2 F9 8A 74 9B A2 A7 3A 7A A4 84 AD AB 8A 8A E3 5F AD B0 7B CB 17 23 AF B6 FB CB 3C 57 B5 BA 4B 7B 57 57 B5 B3 8B FB 57
    BC B4 B4 CB 7B 64 77 B5 B6 CB FB 54 94 BB B3 BB CB 60 A7 B5 B6 8B FB 93 48 B5 B7 3B 7B 47 0B B2 B2 3B BA C8 88 A4 98 F9 87 98 D7 79 92 88 F9 70 C0 9A A1 C9 09 E7 C3 A3 A1 49 7A 84 D4 A6 A8 FA
    3A C0 B0 AE AF 3A BA E3 6B B1 AF FB 8B 4F 17 B6 B4 8B 8B 97 5B B8 B9 BB BB 80 38 B2 B4 3B 8B 77 AB B7 B5 4B BB 7F 8F B6 B9 8B 3B 83 70 B8 B2 CB 7B 74 A7 BA B7 7B 7B 8B 0F B6 B7 BB 4B 14 20 B4
    B2 CB BA E4 67 A1 96 89 47 A7 83 7A 8C 88 89 87 BC 96 99 89 B9 93 F0 A0 A1 79 FA 50 AF A5 A9 3A 7A C7 D7 AD B2 CA 7A E0 17 B2 B2 3B 8B 58 54 B9 BA BB 8B 74 50 B5 B7 3B FB 63 7F B4 BA 3B FB 5F
    94 BB B4 BB 4B 6B 44 B7 B9 BB FB C7 78 B7 BD FB CB C7 BF BA B5 FB 7B 9F 93 B9 B6 BB 8B 9B 5B B9 B0 4B BB 13 9B A2 99 B9 47 87 70 78 8F B8 79 33 94 98 98 B9 C9 AC B7 9E A0 B9 4A 2C 6C A2 A5 8A
    BA C4 C8 AA AF 7A 3A C0 14 AF AC 3B 3B 00 1C B4 B7 BB 3B 07 33 B6 B5 FB FB 5B 54 B0 B7 FB FB 57 27 B4 B4 BB FB 44 0F B1 B3 BB 7B 44 4F BA B8 7B 4B 7F A0 B6 B3 3B 8B 3F 63 B6 B2 BB 8B 3B 3C B2
    AE FB 8B 07 37 9E 93 89 77 BB 98 7B 8F F8 C9 7F EB 9A 97 F9 39 D3 E0 A2 A3 F9 8A 5B 8B A8 AA BA 4A DF D4 AF B0 7A 7B 10 1F B3 B3 3B 3A FC FF B4 B9 4A FB 5B 93 B4 B5 0B BB 5F A7 B8 BB 4B 8B 93
    44 B6 B8 8B 0B 6B 67 B3 BB 3B 8B 8F 94 BA BC FB FB 6C A8 BA B7 8B 8B 8F 84 BD B9 7B 3B 8C 5F B7 AE FB 4B 28 73 A1 97 49 07 B3 D3 7B 92 F8 B9 6C D7 99 9C F9 7A 0C 03 A3 A3 BA 8A 73 9B A5 AC 3A
    7A C4 0F AB B2 8B 4B 17 18 B2 B1 4B 4B 38 34 B3 B7 4B 0B 63 5B B5 B4 8B 0B 84 88 B5 BB BB 7B 8C 7B B9 B6 CB CB 8C A7 B9 B9 BB 3B 9F 78 BB BD 3B 3B CC B8 BA BA 7B 0B D7 AB BE B8 0B 4B 90 5F B7
    B0 CB 4B 63 AB A5 9A B9 C7 73 6C 76 8D 38 09 2F 64 9A 9C C9 B9 AC E7 98 9B B9 BA 27 20 A1 A9 4A 3A A8 94 A8 AF FA 3A BC 1B AC AF BB 7B 38 FF B5 B2 0A 0B 17 8F B4 B7 CB 7B A0 9C B2 B4 BB FB 0F
    50 B8 B9 CB 4B 80 67 B4 B0 FB 3B 63 24 B8 B4 0B BB CB 68 B6 B3 4B FB 47 7B B8 B7 BB FB 27 44 B2 B1 3B 7A A0 B4 A3 8B 78 77 3B 63 73 8D 08 49 3F 84 96 9B 49 49 AB 27 9E A0 BA CA 2F 14 9F A7 BA
    3A 88 B7 A9 AB 4A 8A D3 CF AE AE 4A 4A CF F3 B2 B0 3A 3B 08 77 B3 B4 0B BB 4F 5B B0 B3 8B 8B 04 34 B6 B7 CB 7B 04 20 B1 AF CB FB 27 8F B8 B5 CB 8B B4 48 B5 AF 3B BB 48 70 B3 B4 3B FA F4 F0 B0
    AD 4A 3A 97 17 A4 91 89 F7 A3 C0 79 90 78 09 64 94 99 9C C9 F9 DC 1B 9D 9F 3A FA 78 73 A2 A8 BA CA B7 B7 AD AB CA 3B 0C F7 B0 AE 0A BB 44 E0 B2 B2 BA BA E3 7F B3 B6 8B BB A8 74 B2 B7 FB BB 1F
    78 B6 B9 7B FB 47 68 B2 B0 0B 4B 57 A7 B6 B6 3B BB E4 48 B8 B2 FB CB 73 80 B9 B7 8B 4B 1F 57 B3 B1 4B 7A C8 F8 A4 8F 88 47 67 8B 76 91 C8 49 54 CC 9A 9D B9 09 EF 34 A1 A1 0A 7A 63 57 A3 A8 3A
    8A BF C3 AC AD FA 4B 1C 37 B1 B1 0B FB 3C E3 B3 B3 CA BB 30 9C B5 B8 7B 7B 67 5C B6 B5 3B 7B 2C 70 B4 BA 0B BB 6C 8C B5 B3 CB CB 54 8F B7 B7 CB 0B F4 64 BC B7 CB 4B 94 94 BA B3 BB CB 83 7F B4
    B4 FB 0A 93 3C A5 93 B9 07 74 AB 77 8E B8 09 9C B4 94 9B B9 49 C4 F4 A2 9B F9 8A 5C 7B A3 A9 FA 8A A7 B4 AC B3 FA FB 14 28 AE B3 0B CB 54 2B B7 B6 BB 3B 23 2C B6 B5 FB FB 8B 4F B8 BB 4B BB 48
    A3 B8 B8 7B FB 90 63 B6 BE 4B FB B7 8B BB B5 FB BB 80 BB BB BC 0B 7B 5F AB B9 BA CB 0B AB 70 B6 AF CB 8A CF A3 A8 9A 49 87 5F C4 75 90 48 49 A7 98 94 9B 49 89 AF 24 9C 9F 8A FA 64 40 A6 A9 7A
    BA 84 A0 A7 B1 FA 7A C0 23 B0 AF 4B 8A CB 03 B4 B4 8B 4B 0B 13 AF B5 CB 4B 27 E4 B4 B8 0A BB 27 48 B4 B3 CB 8B 0C 13 B0 B9 FB FB 73 43 B4 B4 CB 0B 24 97 B6 B6 8B CA CC 60 B5 B5 0B 8B 77 63 B4
    B0 FB 7A B8 23 A8 92 49 F7 B0 88 7A 91 38 89 A0 E7 97 9D 89 89 BB 33 A2 A1 3A 8A 73 6C A4 A9 0A CA 8F B4 AC B2 CA 7A D7 14 B0 B0 4B 4B 53 24 B6 B7 3B FB 2B 57 B4 B1 7B 0B 68 53 B6 B7 3B CB 58
    AF B4 B9 0B FB 87 50 B7 BC 7B 3B 6B 60 B7 B4 BB FB 9F A0 BA BC 7B 8B 4B 67 B9 B9 FB BB 8B 84 BA B1 7B FB 0C 3B A6 93 89 77 8C D3 78 90 08 F9 AC BB 9A 9D 39 F9 D8 3B A4 A2 CA 4A 80 87 A4 AB 4A
    0A AC CB B0 B2 4A 8B 37 4C B0 B6 3B 0B 78 20 B5 B7 8B 3B 53 83 B5 B8 3B BB 8C 50 B9 BB BB 4B 4C C7 B8 B9 7B 3B BF B0 B8 BA CB BB 9C 98 BB B8 8B 0B 9F EB B8 B8 8B 8B 84 A8 BC BB 3B BB AB 8F B8
    B0 CB 8B 2B C4 AB 9C 39 87 7C 90 77 89 B8 C9 4C C7 93 9C 09 89 BB DF 9E A1 89 7A 0B 6C A4 A3 4A FA 44 88 AD B1 CA BA AF C4 AD AA 7A 3B 18 17 B1 B5 4B CB 4B 4C B3 B4 8B BB 58 4B B1 B9 BB BB 6F
    3B B9 B5 BB CB 2B 6C B4 B6 FB 4B 7F 10 B5 B2 FB CB 94 87 B8 B7 8B FB 33 50 B6 B6 8B 4B 5B FC B2 B3 4A 4A E3 47 A6 94 49 47 57 73 75 8D B8 F9 53 AF 92 9A F9 49 AC BF A0 A0 79 0A 0F 4B A4 A5 BA
    FA 68 64 AA B0 3A CA D3 F8 AC AC 8A CA FC DB AD B1 7A FB 2C 08 B1 B2 BB 4B 73 67 AE B6 0B FB 1F 17 B6 B2 CB 3A F7 3C B3 B1 3B 4B 5C DC B4 AE 7A FB 5F 4C B7 B1 8B 7B 08 EC B5 B2 BA 0A EB 13 B0
    B1 8B 7A D8 53 A6 95 49 C7 C0 B8 7B 92 38 89 78 D8 94 A0 39 89 CC D8 A4 A5 79 4A 4F C4 A4 A7 FA 8A 80 98 AC AF CA 0A F3 1F AF B1 8B 3B 4F 10 B1 B4 8B 0B 1F 2C B5 B3 FB 4B BF 50 B6 BC FB BB 70
    64 B8 B1 8B FB 94 C0 B6 B8 BB 0B 9B 27 B6 B5 4B FB 70 7B B9 B9 4B CB 3C 28 B9 B8 FB 8B 5B 3F B1 B1 BB 8B 04 8B A5 98 89 87 6C F4 76 92 88 49 B4 DB 97 A2 09 49 D7 33 A5 A2 4A 4A 5C 73 A5 A9 7A
    FA B7 CF AD B1 0A FB 07 37 B0 B5 7B 3B 40 57 B4 B9 7B 8B 4C 60 B8 B3 0B 7B AF 78 B8 BA 3B FB 48 A4 B7 B8 8B 8B C0 B8 B7 B9 3B 3B E7 6B BD B6 8B 7B CC B7 BB BB 8B FB 8C 44 BC BD 7B BB 60 50 B4
    B3 4B 3B 1B 63 AA 96 09 C7 63 77 75 8C F8 F9 74 B8 96 9E 39 89 AC 38 9D A1 0A 8A 40 84 A5 A6 4A 3A BF 97 AD AE 7A 3B 04 08 AC B0 4B FA DF 1B B2 B7 BB CB 28 AF B4 B7 CB FB A4 67 B4 B6 CB 8B 7F
    74 BB B5 BB CB 27 BB B8 BA 4B CB 67 E7 BB B8 BB 7B 7C 78 B9 B8 CB 8B 84 88 BD B9 4B 7B 43 A3 B7 AE BB FB 43 A3 A8 9A 39 07 37 9C 73 8F 88 09 4B C7 96 9B 09 39 C3 E3 9F A0 F9 7A 58 84 A7 A9 FA
    CA 80 BF AA AD 8A 3A F3 53 AC B1 4B 4B 30 D8 B0 B6 FA 0B 4C 83 B2 B4 BB BB 6C 1F B3 B2 FB BB 27 6B B8 B1 CB 4B 27 88 B4 B4 8B 3B 5C 67 B3 B3 CB CB 3F 77 B8 B5 3B 7B 3B 47 B8 B1 8B 0B 27 43 B1
    AE 8B 8A F8 90 A5 98 F9 77 7C B8 77 90 88 C9 5F D4 99 A1 39 89 D8 2B A1 A4 BA 3A 74 C0 A9 A5 4A 4A AC FF AE AF 4A 4B 37 4F B2 B1 0B 4B 0B 57 B6 B9 4B BB 2B 93 B4 B4 3B 3B 93 8B BA B9 7B BB 8F
    8C BF B6 BB FB 30 6C B7 B5 FB 0B 90 CF B5 B9 4B CB 8B AC B9 BC FB 3B 7B 83 BF B8 3B FB 5F 88 B4 B1 0B 3B 4B 93 A6 99 09 07 87 CB 78 91 88 F9 E7 D8 9C A1 79 09 F4 1B A4 A3 7A BA 7C D7 AA A9 CA
    7A CF EC B2 B1 8A 3B 37 6F B3 B2 BB CB 40 7B B7 BA CB CB 67 C8 B8 B6 FB 7B F7 9C B8 BD FB 0B C7 77 BF B8 8B FB 54 C8 BA BA 7B BB B3 BF BA BA 0B BB AB 84 BE BD BB 8B A8 B3 C2 BA 8B 4B 87 8B BD
    B4 CB BB 63 90 A9 99 09 77 7B 48 77 8D 78 09 64 E8 98 9C B9 89 B4 C4 A0 A1 89 3A 6B BC A2 AA FA 3A B8 CB AB AF BA BB 18 4C AD B0 CB 0B 38 6B B4 B6 8B 4B 07 C7 B4 B4 3B 0B 6F A7 B8 B9 FB BB 3B
    4F B9 B6 FB FB 8F 93 BA B7 3B FB 5C 6C B9 B8 CB BB 5C 80 BA B7 FB CB 77 5C B9 B9 7B CB 64 1B B4 B6 4B FA E8 77 A3 97 49 87 5F 64 75 90 08 F9 67 EB 98 9E 79 B9 E4 93 A3 A2 F9 3A 80 A3 A5 A6 0A
    FA 78 AB AB AD BA 3A DB 37 AB AF BB 4A FC 4F B1 B3 BB 4B 04 7B B2 B2 0B FB 3C 4F B3 B3 8B 8B 1C 54 B1 B4 FB 7B 2B 74 B5 B6 4B BB 34 1F B8 B7 3B 4B 94 53 B5 B2 8B 4B 78 27 B8 B4 7B CB 34 0C B4
    AE 4B FA C0 37 9F 93 79 B7 E8 8F 7E 91 48 C9 A7 C4 98 9F 49 49 FB E8 A2 A1 89 BA 9F D4 A7 A8 8A CA A3 CC AA AE 4A 0B 17 44 AE B4 8B 0B 3B A7 B0 B6 8B 7B 3B AF B5 B6 0B 0B 64 D8 B9 B6 8B 3B 73
    7B B7 B7 BB BB A3 98 BB BA FB 7B 74 4F B9 BA 8B FB 8C 64 B9 BA 4B CB AF 6F BC BA 3B BB 78 4F B9 B3 BB 3B 0C B4 A4 9B 49 87 BB DB 7B 95 48 09 70 2F 9C A2 3A CA 1B 2B A5 A6 FA 4A AB 0F AB B0 3B
    7A C8 08 B1 B0 FB 4B 1C 8C B2 B2 CB 0B 64 BB BA B9 BB 7B 74 D7 B9 B6 4B FB 7F A0 BA BA 8B FB 8F 87 BC BB 3B 0B E0 FC BC BD 4B 3B 8C 78 BE BB 4B BB AB 9C C0 B6 FB BB DC A8 BB B9 BB 0B 8F 84 B6
    B5 CB 3B 00 73 A7 97 39 37 8B CB 78 90 F8 C9 78 9F 96 9F 79 BA 03 37 A5 A3 CA 4A 63 8C A8 A9 CA BA 93 C0 AF B3 FA 3A CC 4B B1 B3 FB 8B 5F 47 B9 B8 8B CB 3F C4 B5 B6 CB BB C7 57 B7 BB CB 7B DF
    BC BA BE 8B 7B 74 EB B3 BC 7B 8B 7B E8 B8 BA 4B CB 84 EB BC BC 0B BB BB AF B7 BA BB 7B 9F 8F BA B3 FB FB 2C 3F A7 93 C9 77 1C 3C 71 88 78 08 FB 1F 8E 99 09 79 5F 7B 9D 96 B9 F9 E3 37 9D A1 7A
    7A 17 5B A7 AA 3A 4A 40 D3 A6 AC 7A 4A AF 98 A9 A9 FA 7A D4 E0 AE A9 FA BA FB B4 AC B0 FA 8A DB 07 AD AF 0B 7A E8 E4 A7 AE 0A BA B3 D8 AC AE 3A 3A BB D7 AF AC 4A 3A C4 EF AB AB 3A 4A A8 10 AD
    A5 8B 7A 48 DB 9D 8D C8 F6 8B 90 67 7E 47 F8 3F 98 85 8F B8 78 D8 F8 93 8F 48 B9 48 54 98 9B 39 F9 9C CB 9F 9E C9 FA 1B 1B 9D A1 4A BA 18 CF A3 9E B9 0A 03 7F A5 A2 BA 7A 94 08 A3 A7 4A 0A 60
    78 A7 AB BA BA 78 6B A2 A6 7A 3A 48 5B A3 A1 CA 39 F3 5B A5 A3 BA CA 4C 28 A2 A0 8A 0A 6C 4B A4 9F 4A B9 DF 33 93 82 F8 85 77 00 56 64 C6 C7 44 3B 71 75 07 87 6B 93 7E 7A 37 F7 BC 00 7A 7F 78
    C8 24 4B 85 88 88 B8 8C B7 86 89 88 C8 B8 A8 8A 8B C8 B8 90 E0 8D 8D 38 B9 0F 9C 89 8F 48 49 00 AF 8D 8F 48 08 DC F0 89 8F 38 C8 98 C3 8C 89 C8 F8 AC CF 8A 90 08 C8 A8 C4 8C 8A 48 C8 EF B7 8A
    84 38 08 5B B4 7E 6A C6 E7 5B C9 57 88

    # полный пакет - длина 7693
    # 0x20 - тип пакета, 0A 1E = 0x1E0A = 7690 (полезные данные пакета)
    # отрезали 20 0A 1E - длина теперь 7690
    # отрезали 88 - длина теперь 7689
    # col:80 x row:64 = 5120 pixels
    # 5120 * 1.5 = 7680 - нужная длина данных
    image = image[5:]       # trim header (first 5 0x00 bytes)
    image = payload[:-4]    # trim image crc checksum
```

### setmode: Fdt manual (3)

```
enter, Mode 3, Type 3, base_type 1
setmode: Fdt manual
switch to FDT mode 3

write
    a0 12 00 b2
        a0    - флаг MSG_PROTOCOL
        1200  - полная длина следующего пакета в LE-notation (18)
        a6    - контрольная сумма

    36 0f 00 09 01 80 b0 80 c3 80 a6 80 b8 80 a8 80 b8 2a
        36    - cmd (fdt manual)
        0f00  - длина последующего с контрольной суммой сообщения в LE-notation (15)
        09 01 -
        80 b0 80 c3 80 a6 80 b8 80 a8 80 b8 - data sent::0x80b080c380a680b880a880b8
        2a    - контрольная сумма

read ack
    a0 06 00 a6
        a0    - флаг MSG_PROTOCOL
        0600  - полная длина следующего пакета в LE-notation
        a6    - контрольная сумма

    b0 03 00 36 01 c0
        b0    - cmd ACK
        0300  - длина последующего с контрольной суммой сообщения в LE-notation
        36    - cmd (fdt manual)
        01    - cfg flag 0x1
        c0    - контрольная сумма

read
    a0 14 00 b4
        a0    - флаг MSG_PROTOCOL
        1400  - полная длина следующего пакета в LE-notation (20)
        b4    - контрольная сумма

    36 11 00 00 01 00 00 60 01 87 01 4c 01 71 01 50 01 71 01 f7
        36      - cmd (fdt) cmd1 3
        1100    - длина последующего с контрольной суммой сообщения в LE-notation (17)
        00 01   - IrqStatus:0x100
        00 00 - touchflag 0x0
        60 01 87 01 4c 01 71 01 50 01 71 01 - received fdt base::0x600187014c01710150017101
        f7      - контрольная сумма (не null)

IRQ for fdt-manual, get fdt-up base, current mode is fdt-manual, touchflag 0x0

gf_get_fdtbase 2 finshed

--- base not exist, update imagebase
nav buffer size:3200 buffer size:10240
save imagebase
fail to create dir C:\ProgramData\Goodix, errno 17
write 13520-13520 bytes to C:\ProgramData\Goodix\goodix.dat

```
