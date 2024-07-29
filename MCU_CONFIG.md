```

AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 62
AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 02 00 00 01 00 00 04 25 02 00 00 00 ] 60
AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 14 00 00 01 00 00 04 25 02 00 00 00 ] 4E
AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 15 00 00 01 00 00 04 25 02 00 00 00 ] 4D
AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 17 00 00 01 00 00 04 25 02 00 00 00 ] 4B

AE 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65
AE 17 00 [ 04 00 30 00 00 00 00 01 60 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 24
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 00 00 00 01 00 01 04 25 02 00 00 00 ] 5E
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 01 00 00 01 00 01 04 25 02 00 01 00 ] 5C
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 01 00 00 01 80 01 04 25 02 00 01 00 ] DC
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 02 00 00 01 80 01 04 25 02 00 01 00 ] DB
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 03 00 00 01 80 01 04 25 02 00 03 00 ] D8
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 04 00 00 01 80 01 04 25 02 00 2C 00 ] AE
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 05 00 00 01 80 01 04 25 02 00 2D 00 ] AC
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 06 00 00 01 80 01 04 25 02 00 56 00 ] 82
AE 17 00 [ 04 06 30 00 00 00 00 01 20 00 00 00 00 01 00 01 04 25 02 00 00 00 ] 5D


                                03                                     56
              06                01 60                80 01             01
           04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00
           \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \/ \___/ \/ \/ \/ \/
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │   │    │  │  │  └─ otp_mcu_check_status : 0x0
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │   │    │  │  └──── normal_capture_count : 0
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │   │    │  └─────── pov_capture_count : 0
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │   │    └────────── sensor_type : 2
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  │   └─────────────── sensor_chip_id : 0x2504
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  │  └─────────────────── config_down_flag : 0        0000 0001
            │  │  │  │  │  │  │  │  │  │  │  │  │  │  └────────────────────── pov_procedure : 0x0
            │  │  │  │  │  │  │  │  │  │  │  │  │  └───────────────────────── pov_wake_by_ec : 0
            │  │  │  │  │  │  │  │  │  │  │  │  └──────────────────────────── pov_wake_by_fp : 1
            │  │  │  │  │  │  │  │  │  │  │  └─────────────────────────────── system_up_cleared_pov_count : 0
            │  │  │  │  │  │  │  │  │  │  └────────────────────────────────── system_down_pov_stop_cnt : 0
            │  │  │  │  │  │  │  │  │  └───────────────────────────────────── system_up_stop_cnt : 0
            │  │  │  │  │  │  │  │  └──────────────────────────────────────── ec_falling_count : 0
            │  │  │  │  │  │  │  └─────────────────────────────────────────── psk_write_fail : 0
            │  │  │  │  │  │  └──────────────────────────────────────────────
            │  │  │  │  │  └─────────────────────────────────────────────────
            │  │  │  │  └────────────────────────────────────────────────────
            │  │  │  └───────────────────────────────────────────────────────
            │  │  └──────────────────────────────────────────────────────────
            │  └─────────────────────────────────────────────────────────────
            └──────────────────────────────────────────────────────────────── version : 4

AE 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65
           \/ \/ \/ \/ \/ \/ \/ \/ \/    \/       \/ \/ \/ \___/ \/ \/ \/ \/
            1  2  3             14 15    17       23 24 25   26  27 28 29 30

1  version : 4

2  isPOVImageValid : 0             0000 1000
2  isTlsConnected : 0              0000 0100
2  isTlsUsed : 0                   0000 0010
2  isLocked : 0                    0000 0001

   availImgCnt : 0
3  povImgCnt : 3

   sensor_data_int_timeout_count : 0
   image_crc_fail_count : 0
   povTouchAccidentCnt : 0x0
   readChipIDCnt : 0

   sensorExceptionFlag : 0
   sensorUnexpectedIntCnt : 0
14 to_master_timeout_count : 0

15 psk_len : 32                0010 0000
15 psk_check_fail : 0          0001 1100
   psk_write_fail : 0
   ec_falling_count : 0
17 system_up_stop_cnt : 0
   system_down_pov_stop_cnt : 0
   system_up_cleared_pov_count : 0
23 pov_wake_by_fp : 1
   pov_wake_by_ec : 0
24 pov_procedure : 0x0
25 config_down_flag : 0        0000 0001
26 sensor_chip_id : 0x2504
27 sensor_type : 2
28 pov_capture_count : 0
29 normal_capture_count : 0
30 otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65

version : 4
isPOVImageValid : 0
isTlsConnected : 0
isTlsUsed : 0
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 0
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x0
config_down_flag : 0
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 0
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 00 00 00 01 00 01 04 25 02 00 00 00 ] 5E

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 0
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x0
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 0
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 01 00 00 01 80 01 04 25 02 00 01 00 ] DC

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 1
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 1
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 02 00 00 01 80 01 04 25 02 00 01 00 ] DB

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 2
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 1
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 05 00 00 01 80 01 04 25 02 00 2D 00 ] AC

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 5
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 45
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 06 00 00 01 80 01 04 25 02 00 56 00 ] 82

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 6
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 86
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 00 30 00 00 00 00 01 60 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 24

version : 4
isPOVImageValid : 0
isTlsConnected : 0
isTlsUsed : 0
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 1
psk_len : 32
psk_check_fail : 1
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 0
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x0
config_down_flag : 0
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 0
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 01 20 00 00 00 00 01 00 01 04 25 02 00 00 00 ] 5D

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 1
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 0
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x0
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 0
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 01 00 00 01 00 01 04 25 02 00 01 00 ] 5C

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 1
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x0
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 1
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 03 00 00 01 80 01 04 25 02 00 03 00 ] D8

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 3
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 3
otp_mcu_check_status : 0x0
```

-----------------------------------------------------------------------------------------------------------------------
```
AE 17 00 [ 04 06 30 00 00 00 00 00 20 00 04 00 00 01 80 01 04 25 02 00 2C 00 ] AE

version : 4
isPOVImageValid : 0
isTlsConnected : 1
isTlsUsed : 1
isLocked : 0
availImgCnt : 0
povImgCnt : 3
sensor_data_int_timeout_count : 0
image_crc_fail_count : 0
povTouchAccidentCnt : 0x0
readChipIDCnt : 0
sensorExceptionFlag : 0
sensorUnexpectedIntCnt : 0
to_master_timeout_count : 0
psk_len : 32
psk_check_fail : 0
psk_write_fail : 0
ec_falling_count : 0
system_up_stop_cnt : 4
system_down_pov_stop_cnt : 0
system_up_cleared_pov_count : 0
pov_wake_by_fp : 1
pov_wake_by_ec : 0
pov_procedure : 0x80
config_down_flag : 1
sensor_chip_id : 0x2504
sensor_type : 2
pov_capture_count : 0
normal_capture_count : 44
otp_mcu_check_status : 0x0
```
