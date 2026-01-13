import unittest

from mcu_state import parse_mcu_state


def _parse_hex_payload(hex_bytes: str) -> bytes:
    return bytes.fromhex(hex_bytes.replace(" ", ""))


class TestParseMcuState(unittest.TestCase):
    def test_example_base_state(self) -> None:
        payload = _parse_hex_payload(
            "04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00"
        )
        state = parse_mcu_state(payload)
        self.assertEqual(state["version"], 4)
        self.assertEqual(state["isPOVImageValid"], 0)
        self.assertEqual(state["isTlsConnected"], 0)
        self.assertEqual(state["isTlsUsed"], 0)
        self.assertEqual(state["isLocked"], 0)
        self.assertEqual(state["availImgCnt"], 0)
        self.assertEqual(state["povImgCnt"], 3)
        self.assertEqual(state["to_master_timeout_count"], 0)
        self.assertEqual(state["psk_len"], 32)
        self.assertEqual(state["psk_check_fail"], 0)
        self.assertEqual(state["config_down_flag"], 0)
        self.assertEqual(state["sensor_chip_id"], 0x2504)
        self.assertEqual(state["sensor_type"], 2)
        self.assertEqual(state["pov_capture_count"], 0)
        self.assertEqual(state["normal_capture_count"], 0)
        self.assertEqual(state["otp_mcu_check_status"], 0)

    def test_example_tls_and_config_down(self) -> None:
        payload = _parse_hex_payload(
            "04 06 30 00 00 00 00 00 20 00 00 00 00 01 00 01 04 25 02 00 00 00"
        )
        state = parse_mcu_state(payload)
        self.assertEqual(state["isTlsConnected"], 1)
        self.assertEqual(state["isTlsUsed"], 1)
        self.assertEqual(state["config_down_flag"], 1)

    def test_example_pov_procedure_and_counts(self) -> None:
        payload = _parse_hex_payload(
            "04 06 30 00 00 00 00 00 20 00 01 00 00 01 80 01 04 25 02 00 01 00"
        )
        state = parse_mcu_state(payload)
        self.assertEqual(state["system_up_stop_cnt"], 1)
        self.assertEqual(state["pov_procedure"], 0x80)
        self.assertEqual(state["config_down_flag"], 1)
        self.assertEqual(state["normal_capture_count"], 1)

    def test_example_timeout_and_psk_check_fail(self) -> None:
        payload = _parse_hex_payload(
            "04 00 30 00 00 00 00 01 60 00 00 00 00 01 00 00 04 25 02 00 00 00"
        )
        state = parse_mcu_state(payload)
        self.assertEqual(state["to_master_timeout_count"], 1)
        self.assertEqual(state["psk_len"], 32)
        self.assertEqual(state["psk_check_fail"], 1)
        self.assertEqual(state["psk_write_fail"], 0)

    def test_example_normal_capture_count(self) -> None:
        payload = _parse_hex_payload(
            "04 06 30 00 00 00 00 00 20 00 05 00 00 01 80 01 04 25 02 00 2D 00"
        )
        state = parse_mcu_state(payload)
        self.assertEqual(state["system_up_stop_cnt"], 5)
        self.assertEqual(state["normal_capture_count"], 45)
        self.assertEqual(state["pov_procedure"], 0x80)


if __name__ == "__main__":
    unittest.main()
