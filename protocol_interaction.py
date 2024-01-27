import threading
from time import sleep

import periphery
from periphery import CdevGPIO
from spidev import SpiDev

from util_fmt import Colors, log, to_hex_string, to_utf_string, format_validity


def make_protocol_packet(packet_type: int, payload_length: int) -> bytearray:
    """
    packet_type
        0xA0
        0xB0

    payload_length
        length of payload packet
    """
    protocol_packet = bytearray([packet_type]) + payload_length.to_bytes(2, 'little')
    checksum: bytes = sum(protocol_packet).to_bytes()
    protocol_packet += checksum

    return protocol_packet


def reset_spi():
    log(Colors.RED, "reset device...")
    gpio_reset = CdevGPIO('/dev/gpiochip0', 140, 'out', label='fp-reset')
    for i in (1, 0):
        gpio_reset.write(bool(i))
    gpio_reset.close()


def is_checksum_valid(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    fact_sum = sum(packet[:-1])
    fact_sum_first_byte = fact_sum.to_bytes(10, byteorder="little")[0]
    return checksum == fact_sum_first_byte


def extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int


def perform_read(spi: SpiDev) -> list[int]:
    log(Colors.LIGHT_BLUE, log_prefix + "reading from device...")
    packet_1 = spi.readbytes(4)
    is_valid = is_checksum_valid(packet_1)
    log(Colors.LIGHT_BLUE, log_prefix +
        f"\t- received packet 1 {format_validity(is_valid) + Colors.BLUE} : {to_hex_string(packet_1)}")
    length = extract_length(packet_1)
    packet_2 = spi.readbytes(length)
    is_valid = is_checksum_valid(packet_2)
    log(Colors.LIGHT_BLUE, log_prefix +
        f"\t- received packet 2 {format_validity(is_valid) + Colors.BLUE} : {to_hex_string(packet_2)} | {to_utf_string(packet_2)}")
    return packet_2


def perform_write(spi: SpiDev, packet_type: int, payload: bytes | str | list[int]):
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    elif isinstance(payload, list):
        payload = bytearray(payload)

    log(Colors.LIGHT_PURPLE, log_prefix + "writing to device...")
    protocol_packet = make_protocol_packet(packet_type, len(payload))
    spi.writebytes(protocol_packet)
    log(Colors.LIGHT_PURPLE, log_prefix + f"\t- protocol packet sent: {to_hex_string(protocol_packet)}")
    spi.writebytes(payload)
    log(Colors.LIGHT_PURPLE, log_prefix +
        f"\t-  payload packet sent: {to_hex_string(payload)} | {to_utf_string(payload)}")


def perform_tx(spi: SpiDev, gpio_line: CdevGPIO, packet_type: int, payload: bytes | str | list) -> list[int]:
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    elif isinstance(payload, list):
        payload = bytearray(payload)

    global log_prefix
    log_prefix = "┃ "

    print("┏━━━ read-write ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    ready_to_write_lock = threading.Lock()
    ready_to_write_lock.acquire()
    print("latch created")
    print("┃ locks acquired")

    ir_thread = threading.Thread(target=interrupt_monitoring, args=(gpio_line, ready_to_write_lock))
    # ir_thread.daemon = True
    ir_thread.start()
    ready_to_write_lock.acquire()
    sleep(0.01)  # delay so that the interrupt thread has time to enter gpio_line.read_event()

    perform_write(spi, packet_type, payload)

    print("┃ waiting for gpio interrupt...")
    ir_thread.join(timeout=3)
    if ir_thread.is_alive():
        exit(1)

    print("┃ interrupt caught, execution goes on")

    result = perform_read(spi)
    print("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log_prefix = ""
    return result


def interrupt_monitoring(gpio_line: periphery.CdevGPIO, ready_to_write_lock: threading.Lock):
    log(Colors.CYAN, "interrupt_monitoring started")
    ready_to_write_lock.release()
    i = 1
    while True:
        event = gpio_line.read_event()
        if event.edge == 'rising' and i >= 100:
            log(Colors.CYAN, f"release read lock on iteration {i}")
            return True
        i += 1
        # sleep(0.001)


def main():
    gpio_line = CdevGPIO('/dev/gpiochip0', 321, 'in', edge='both', bias='default')
    spi = SpiDev(1, 0)
    spi.max_speed_hz = 0x00989680  # 10 000 000
    # spi.mode = 0b00

    # reset_spi()
    sleep(0.1)

    # possible values '00' or  [0x00] or bytearray([0x00])

    # ----------------------------------------------------------------------------------------------------------------
    # init ?

    perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    perform_write(spi, 0xa0, 'd5 03 00 00 00 d3')

    # ----------------------------------------------------------------------------------------------------------------
    # # get evk version: GF_HC460SEC_APP_14210

    perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    perform_tx(spi, gpio_line, 0xa0, 'a8 03 00 00 00 ff')
    perform_read(spi)

    # ----------------------------------------------------------------------------------------------------------------
    # get mcu state

    #  write    9 -  0000: af 06 00 55 5c bf 00 00 86
    #   read    4 -  0000: a0 1a 00 ba
    #   read   26 -  0000: ae 17 00  [ 04 00 30 00 00 00 00 00(3) 20 00 00(2) 00 00 01 00 00 04 25 02 00 00 00 ] 65
    #                                  \/ \/ \/ \/          \/    \/                \/    \/ \___/ \/
    #                                   1  2                14    15                23    25   26  27

    #  1  version:4

    #  2  isPOVImageValid:0     bit
    #  2  isTlsConnected:0      bit
    #  2  isTlsUsed:0           bit
    #  2  isLocked:0            bit

    #     availImgCnt:0
    #     povImgCnt:3
    #     sensor_data_int_timeout_count:0
    #     image_crc_fail_count:0
    #     povTouchAccidentCnt:0x0
    #     readChipIDCnt:0

    #     sensorExceptionFlag:0
    #     sensorUnexpectedIntCnt:0
    #     to_master_timeout_count:0
    #  15 psk_len:32
    #     psk_check_fail:0
    #     psk_write_fail:0
    #     ec_falling_count:0
    #     system_up_stop_cnt:0
    #     system_down_pov_stop_cnt:0
    #     system_up_cleared_pov_count:0
    #  23 pov_wake_by_fp:1
    #     pov_wake_by_ec:0
    #     pov_procedure:0x0
    #  25 config_down_flag:0
    #  26 sensor_chip_id:0x2504
    #  27 sensor_type:2
    #     pov_capture_count:0
    #     normal_capture_count:0
    #     otp_mcu_check_status:0x0

    # эталонный
    # AE 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65
    # linux
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 02 00 00 01 00 00 04 25 02 00 00 00 ] 60

    now = datetime.now()
    now_milliseconds = now.second * 1000 + now.microsecond // 1000
    millis = to_hex_string(now_milliseconds.to_bytes(2, 'little'))

    perform_tx(spi, gpio_line, 0xa0, 'af 06 00 55 5c bf 00 00 86')  # 5c bf = 0xbf5c - это секунды + миллисекунды
    # - received packet 1 🟢 : A0 1A 00 BA
    # - received packet 2 🔴 : AE 17 00 04 00 30 00 00 00 00 03 20 00 02 00 00 01 00 00 04 25 02 00 00 00 60
    # ----------------------------------------------------------------------------------------------------------------

    spi.close()
    gpio_line.close()


log_prefix = ''

if __name__ == "__main__":
    main()
