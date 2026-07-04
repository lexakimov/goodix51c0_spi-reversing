
def parse_mcu_state(payload: bytes) -> dict:
    if len(payload) != 22:
        raise ValueError(f"expected 22 bytes, got {len(payload)}")

    b = payload

    return {
        "version": b[0],

        "is_pov_image_valid": (b[1] >> 0) & 1,
        "is_tls_connected": (b[1] >> 1) & 1,
        "is_tls_used": (b[1] >> 2) & 1,
        "is_locked": (b[1] >> 3) & 1,

        "avail_img_cnt": b[2] & 0x0F,
        "pov_img_cnt": (b[2] >> 4) & 0x0F,

        "sensor_data_int_timeout_count": b[3],
        "image_crc_fail_count": b[4],
        "pov_touch_accident_cnt": b[5] & 0x7F,
        "read_chip_id_cnt": b[6] & 0x07,

        "sensor_exception_flag": (b[6] >> 3) & 1,
        "sensor_unexpected_int_cnt": (b[6] >> 4) & 0x0F,

        "to_master_timeout_count": b[7],

        "psk_len": b[8] & 0x3F,
        "psk_check_fail": (b[8] >> 6) & 1,
        "psk_write_fail": (b[8] >> 7) & 1,

        "ec_falling_count": b[9],

        "system_up_stop_cnt": b[10],
        "system_down_pov_stop_cnt": b[11],
        "system_up_cleared_pov_count": b[12],

        "pov_wake_by_fp": (b[13] >> 0) & 1,
        "pov_wake_by_ec": (b[13] >> 1) & 1,
        "pov_procedure": b[14],

        "config_down_flag": b[15],

        "sensor_chip_id": b[16] | (b[17] << 8),
        "sensor_type": b[18],

        "pov_capture_count": b[19],
        "normal_capture_count": b[20],
        "otp_mcu_check_status": b[21],
    }


def main():
    payload = bytes.fromhex('04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00'.replace(" ", ""))
    mcu_state = parse_mcu_state(payload)
    for k,v in mcu_state.items():
        print(f"{k} : {v}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
