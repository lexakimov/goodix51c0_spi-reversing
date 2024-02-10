
types_by_code: dict[int, str] = {
    0x16: 'GET TLS HANDSHAKE',
    0x20: 'IMAGE',
    0x32: 'FDT DOWN',
    0x34: 'FDT UP',
    0x36: 'FDT MANUAL',
    0x50: 'SETMODE: NAV',
    0x70: 'SETMODE: IDLE',
    0x82: 'MILAN_CHIP_ID',
    0x98: 'SEND DAC',
    0xA0: 'HEADER',
    0xA2: 'RESET',
    0xA6: 'OTP',
    0xA8: 'FIRMWARE VERSION',
    0xAE: 'MCU STATE',
    0xB0: 'ACK',
    0xE4: 'PSK HASH',
}



# Mode 2, Type 0, base_type 0
# setmode: Image
# write    4 -  0000: a0 06 00 a6
# write    6 -  0000: 20 03 00 01 00 86
#
# Mode 2, Type 1, base_type 0
# setmode: Image
# cmd0-cmd1-Len-ackt-ec:0x2-1-0x2-1000-0
# write    4 -  0000: a0 06 00 a6
# write    6 -  0000: 22 03 00 01 00 84


# 0x0 NOP
# 0x2 Ima
# 0x3 FDT(dow/up/man)
# 0x4 FF
# 0x6 Sle
# 0x8 REG
# 0x9 CHIP
# 0xA OTHER
# 0xB MSG
# 0xC NOTI
# 0xD TLSCONN
# 0xE PROD
# 0xF UPFW

# https://gitlab.freedesktop.org/libfprint/libfprint/uploads/0fe6a24764d34354f5d0b8e376c20bf4/WBDI.log
# https://gitlab.freedesktop.org/libfprint/libfprint/uploads/d04ef525a4752b6907b6e0c40a96bd69/WBDI.log

# // Packettype A0. Normal, plaintext packet.
# // Packettype B0. Used during TLS handshake
# // Packettype B2. Used when sending TLS encrypted image data
