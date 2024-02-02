import sys
import time
from datetime import datetime
from threading import Lock, Thread
from time import sleep

from periphery import CdevGPIO
from periphery.gpio import GPIOError
from spidev import SpiDev

from util_fmt import Colors, log, to_hex_string, to_utf_string, format_validity


def log_locks(read_is_ready: Lock, read_is_done: Lock):
    status_1 = '🔒' if read_is_ready.locked() else '🆓'
    status_2 = '🔒' if read_is_done.locked() else '🆓'
    log(Colors.BLUE, f"read_is_ready: {status_1}  read_is_done : {status_2}")


def manual_sleep(duration):
    log(Colors.YELLOW, f"manual sleep for {duration}s")
    sleep(duration)
    log(Colors.YELLOW, "go on...")


def acquire_then_release(lock, label):
    log('\033[48;5;0m', f"acquire {label}...")
    lock.acquire()
    log('\033[48;5;0m', f"release {label}...")
    lock.release()


def make_protocol_packet(packet_type: int, payload_length: int) -> bytearray:
    """
    packet_type
        0xA0
        0xB0

    payload_length
        length of payload packet
    """
    protocol_packet = bytearray([packet_type]) + payload_length.to_bytes(2, 'little')
    sum_int = 0x00
    for b in protocol_packet:
        sum_int = (sum_int + b) & 0xFF
    checksum: bytes = sum_int.to_bytes()
    protocol_packet += checksum

    return protocol_packet


def is_protocol_packet_checksum_valid(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    fact_sum = sum(packet[:-1]) & 0xff
    return checksum == fact_sum


def is_payload_packet_checksum_valid(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    if checksum == 0x88:
        return True
    fact_sum = 0xaa - sum(packet[:-1]) & 0xff
    return checksum == fact_sum


def extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int


def locks_debugging(read_is_ready: Lock, read_is_done: Lock):
    while True:
        log_locks(read_is_ready, read_is_done)
        sleep(0.2)


def reset_spi():
    gpio_reset = CdevGPIO('/dev/gpiochip0', 140, 'out', label='goodix-fp-reset')
    for i in (1, 0):
        gpio_reset.write(bool(i))
        sleep(0.01)
    gpio_reset.close()


def perform_read(spi: SpiDev) -> list[int]:
    log(Colors.HI_BLUE, log_prefix + "reading from device...")
    packet_1 = spi.readbytes(4)
    is_valid = is_protocol_packet_checksum_valid(packet_1)
    validity = format_validity(is_valid)
    hex_string = to_hex_string(packet_1)
    log(Colors.HI_BLUE, f"{log_prefix}\t   - received packet 1 {validity} : {hex_string}")

    if packet_1 == [0, 0, 0, 0]:
        raise RuntimeError('read error: 00 00 00 00 bytes are received')

    length = extract_length(packet_1)
    if length == 0xFFFF:
        raise RuntimeError('read error: FF bytes are received')

    packet_2 = spi.readbytes(length)
    is_valid = is_payload_packet_checksum_valid(packet_2)
    validity = format_validity(is_valid)
    hex_string = to_hex_string(packet_2)
    utf_string = to_utf_string(packet_2)
    log(Colors.HI_BLUE, f"{log_prefix}\t   - received packet 2 {validity} : {hex_string} | {utf_string}")
    return packet_2


def perform_write(spi: SpiDev, packet_type: int, payload: bytes | str | list[int]):
    """
    :param spi: SPI device
    :param packet_type:
    :param payload:      possible values '00' or  [0x00] or bytearray([0x00])
    """
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    elif isinstance(payload, list):
        payload = bytearray(payload)

    log(Colors.HI_PURPLE, log_prefix + "writing to device...")
    protocol_packet = make_protocol_packet(packet_type, len(payload))
    is_1_valid = is_protocol_packet_checksum_valid(protocol_packet)
    is_2_valid = is_payload_packet_checksum_valid(payload)
    spi.writebytes(protocol_packet)
    validity = format_validity(is_1_valid)
    hex_string = to_hex_string(protocol_packet)
    log(Colors.HI_PURPLE, f"{log_prefix}\t- protocol packet sent {validity} : {hex_string}")
    spi.writebytes(payload)
    validity = format_validity(is_2_valid)
    hex_string = to_hex_string(payload)
    utf_string = to_utf_string(payload)
    log(Colors.HI_PURPLE, f"{log_prefix}\t-  payload packet sent {validity} : {hex_string} | {utf_string}")


def interrupt_monitoring(gpio_line: CdevGPIO, read_is_ready: Lock, read_is_done: Lock):
    is_high = False
    i = 0
    last_ts = time.time_ns()
    log(Colors.CYAN, "interrupt_monitoring started")
    while True:
        i += 1
        try:
            # event = gpio_line.read_event()
            current_state = gpio_line.read()
        except GPIOError:
            log(Colors.CYAN, "gpio is closed")
            break

        # event_edge = event.edge
        # event_time = event.timestamp
        # if event_edge == 'rising' and not is_high:
        event_time = time.time_ns()
        if current_state and not is_high:
            passed_ms = int((event_time - last_ts) / 1000000)
            log(Colors.CYAN, f"gpio interrupt: rising  [iteration {i}] {passed_ms}ms) - data ready to read")
            if read_is_ready.locked():
                read_is_ready.release()
            else:
                log(Colors.RED, "trying to release unlocked read_is_ready")
            is_high = True
            last_ts = event_time
            i = 0

        # if event_edge == 'falling' and is_high:
        if not current_state and is_high:
            passed_ms = int((event_time - last_ts) / 1000000)
            log(Colors.CYAN, f"gpio interrupt: falling [iteration {i}] {passed_ms}ms) - reading completed")
            if read_is_done.locked():
                read_is_done.release()
            else:
                log(Colors.RED, "trying to release unlocked read_is_done")
            is_high = False
            i = 0
        sleep(0.01)


def main():
    gpio_line = CdevGPIO('/dev/gpiochip0', 321, 'in', edge='both', bias='default')
    spi = SpiDev(1, 0)
    spi.max_speed_hz = 0x00989680  # 10 000 000
    # spi.mode = 0b00

    read_is_ready = Lock()
    read_is_done = Lock()
    # dbg_thread = Thread(daemon=True, target=locks_debugging, args=(read_is_ready, read_is_done))
    # dbg_thread.start()
    isr_thread = Thread(daemon=True, target=interrupt_monitoring, args=(gpio_line, read_is_ready, read_is_done))
    isr_thread.start()
    sleep(0.05)  # delay so that the interrupt thread has time to enter gpio_line.read_event()

    log(Colors.RED, "reset device...")
    read_is_ready.acquire()
    read_is_done.acquire()
    reset_spi()
    read_is_done.acquire()
    read_is_done.release()
    read_is_ready.acquire()
    read_is_ready.release()
    log(Colors.RED, "reset done")

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ init ".ljust(120, '━'))

    perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    perform_write(spi, 0xa0, 'd5 03 00 00 00 d3')
    manual_sleep(0.1)  # если после записи нет прерывания надо подождать

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get evk version ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    manual_sleep(0.05)
    perform_write(spi, 0xa0, 'a8 03 00 00 00 ff')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get mcu state ".ljust(120, '━'))

    now = datetime.now()
    now_milliseconds = now.second * 1000 + now.microsecond // 1000
    millis = to_hex_string(now_milliseconds.to_bytes(2, 'little'))

    read_is_ready.acquire()
    read_is_done.acquire()
    perform_write(spi, 0xa0, 'af 06 00 55 5c bf 00 00 86')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # A0 1A 00 BA
    # AE 17 00 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 65

    # AE 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 02 00 00 01 00 00 04 25 02 00 00 00 ] 60
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 14 00 00 01 00 00 04 25 02 00 00 00 ] 4E
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 15 00 00 01 00 00 04 25 02 00 00 00 ] 4D
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 17 00 00 01 00 00 04 25 02 00 00 00 ] 4B
    # AE 17 00 [ 04 00 30 00 00 00 00 03 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 62

    # ae 17 00 [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65
    #            \/ \/ \/ \/          \/ \/    \/       \/ \/ \/ \___/ \/ \/ \/ \/
    #             1  2  3             14 15    17       23 24 25   26  27 28 29 30

    #  1  version:4

    #  2  isPOVImageValid:0     bit
    #  2  isTlsConnected:0      bit
    #  2  isTlsUsed:0           bit
    #  2  isLocked:0            bit

    #  3  availImgCnt:0
    #  3  povImgCnt:3

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
    #  17 system_up_stop_cnt:0
    #     system_down_pov_stop_cnt:0
    #     system_up_cleared_pov_count:0
    #  23 pov_wake_by_fp:1
    #     pov_wake_by_ec:0
    #  24 pov_procedure:0x0
    #  25 config_down_flag:0
    #  26 sensor_chip_id:0x2504
    #  27 sensor_type:2
    #  28 pov_capture_count:0
    #  29 normal_capture_count:0
    #  30 otp_mcu_check_status:0x0

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ PSK INIT - get host_psk_data ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()
    perform_write(spi, 0xa0, 'e4 09 00 02 00 01 bb 00 00 00 00 ff')     # read specific data_type 0xbb010002
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    manual_sleep(0.05)
    perform_read(spi)                                               # содержит Goodix_Cache.bin
    acquire_then_release(read_is_done, 'read_is_done')

    # # полный пакет [длина 345]
    # e4
    # 56 01 [указание полезной длины + контрольная сумма = 342]
    # 00
    # # specific data_type 0xbb010002 (был указан в запросе)
    # 02 00 01 bb
    # # длина host_psk_data (332)
    # 4c 01
    # 00 00
    # # далее host_psk_data (содержимое Goodix_Cache.bin, длина 332)
    # 01 00 00 00
    # d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb
    # 01 00 00 00 ce 4b 48 a6 19 9f e1 4c a7 a3 2e 7a
    # 0e 0b 6b 59 04 00 00 00 40 00 00 00 54 00 68 00
    # 69 00 73 00 20 00 69 00 73 00 20 00 74 00 68 00
    # 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00
    # 70 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00
    # 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00
    # 00 01 00 00 20 00 00 00 d7 77 c2 10 c1 bc 73 d2
    # 87 fb 57 99 53 16 39 0e 39 eb 6a d0 43 cd 08 19
    # e0 82 a6 cb 14 8b 38 47 00 00 00 00 0e 80 00 00
    # 00 02 00 00 20 00 00 00 e9 2d 13 48 1b e6 8b 22
    # b5 b3 7a b3 9a 65 4b 3e 73 f6 6a a7 af 47 49 31
    # a6 4c 47 84 bd c4 32 f9 30 00 00 00 15 67 c9 fc
    # 68 79 ba 11 cc 3e fb 30 82 be 3a b7 1c 18 f9 cd
    # ef 08 0d dc 1a b9 17 79 17 9b 79 42 73 1a b8 2d
    # 8e 31 b6 8a 0f b1 cb 3b 0c 83 15 8e 40 00 00 00
    # ee b8 30 22 43 74 f3 15 cf 0c 60 c9 c7 40 32 6f
    # 7e e7 99 f2 21 75 11 58 d2 71 59 33 66 ed a7 a3
    # 43 66 12 5b e1 11 73 2a a3 59 83 1e 83 66 50 88
    # f4 2c 6f c8 f7 5e 93 3d 07 c9 97 fc 05 f9 30 9c
    # b6 a0 6b f1 a4 18 8a cf
    #
    # .. контрольная сумма
    # 3b

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ PSK INIT - get psk ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'e4 09 00 03 00 02 bb 00 00 00 00 fd')     # read specific data_type 0xbb020003
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # A0 2D 00 CD

    # # полный пакет [длина 45]
    # E4
    # 2A 00 [указание полезной длины + контрольная сумма = 42]
    # 00
    # # specific data_type 0xbb020003 (был указан в запросе)
    # 03 00 02 BB
    # # длина psk (32)
    # 20 00
    # 00 00
    # # далее psk (длина 32)
    # FB 67 D3 ED E2 44 FF EE B2 76 3C B5 0E E3 81 A3 E6 18 D5 23 8D 61 94 53 43 35 8D 08 0F D0 2D A7 [len 32] PSK
    #
    # # контрольная сумма
    # CE

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ reset sensor; reset device, reset_flag 1 ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a2 03 00 01 14 f0')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')
    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    #  Goodix>>> reset sensor
    #  Goodix>>> reset device, reset_flag 1
    #  Goodix>>> cmd0-cmd1-Len-ackt-ec:0xa-1-0x2-1000-0
    #  write    4 -  0000: a0 06 00 a6
    #  write    6 -  0000: a2 03 00 01 14 f0
    #   read    4 -  0000: a0 06 00 a6
    #   read    6 -  0000: b0 03 00 a2 07 4e
    #  Goodix>>> recvd data cmd-len: 0xb0-3
    #  Goodix>>> get ack for cmd 0xa2, cfg flag 0x7
    #  Goodix>>> MCU has no config
    #   read    4 -  0000: a0 07 00 a7
    #   read    7 -  0000: a2 04 00 01 00 08 fb
    #  Goodix>>> recvd data cmd-len: 0xa2-4
    #  Goodix>>> --- cmd: other
    #  Goodix>>> CHIP_RESET::0x010008

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ MILAN_CHIPID (cmd: regrw) ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '82 06 00 00 00 00 04 00 1e')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    #  Goodix>>> --- MILAN_CHIPID
    #  Goodix>>> cmd0-cmd1-Len-ackt-ec:0x8-1-0x5-1000-0
    #  write    4 -  0000: a0 09 00 a9
    #  write    9 -  0000: 82 06 00 00 00 00 04 00 1e
    #   read    4 -  0000: a0 06 00 a6
    #   read    6 -  0000: b0 03 00 82 07 6e
    #  Goodix>>> recvd data cmd-len: 0xb0-3
    #  Goodix>>> get ack for cmd 0x82, cfg flag 0x7
    #  Goodix>>> MCU has no config
    #   read    4 -  0000: a0 08 00 a8
    #   read    8 -  0000: 82 05 00 a2 04 25 00 58
    #  Goodix>>> recvd data cmd-len: 0x82-5
    #  Goodix>>> --- cmd: regrw

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ to set state to DEVICE_ACTION, to set state from 1 to 3 ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a6 03 00 00 00 01')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')
    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # A6
    # длина (65)
    # 41 00
    # OTP (хранится в goodix.dat) длина 64
    # 53 34 30 36 36 36 2E 00 0A 7D 82 B3 72 A0 46 0A 51 07 05 0E 7D 4B 17 27 41 02 9A 0C F1 80 7F 0C 07 81 30 38 E4 80 DD FC 0A BE BB 44 01 BB B3 B5 B3 B3 B3 B5 B3 B3 41 33 E4 1B DD 22 0C F0 17 DB
    # контроль
    # 1C

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ reset sensor; reset device, reset_flag 1 ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a2 03 00 01 14 f0')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')
    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    #  Goodix>>> reset sensor
    #  Goodix>>> reset device, reset_flag 1
    #  Goodix>>> cmd0-cmd1-Len-ackt-ec:0xa-1-0x2-1000-0
    #  write    4 -  0000: a0 06 00 a6
    #  write    6 -  0000: a2 03 00 01 14 f0
    #   read    4 -  0000: a0 06 00 a6
    #   read    6 -  0000: b0 03 00 a2 07 4e
    #  Goodix>>> recvd data cmd-len: 0xb0-3
    #  Goodix>>> get ack for cmd 0xa2, cfg flag 0x7
    #  Goodix>>> MCU has no config
    #   read    4 -  0000: a0 07 00 a7
    #   read    7 -  0000: a2 04 00 01 00 08 fb
    #  Goodix>>> recvd data cmd-len: 0xa2-4
    #  Goodix>>> --- cmd: other
    #  Goodix>>> CHIP_RESET::0x010008

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ enter, Mode 7, Type 0, base_type 0; setmode: idle ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '70 03 00 14 00 23')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ send Dac 0x380bb500b300b300 ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '98 09 00 38 0b b5 00 b3 00 b3 00 ab')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get image ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '20 03 00 01 00 86')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')
    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # ----------------------------------------------------------------------------------------------------------------
    # manual_sleep(3)
    log(Colors.NEGATIVE, "closing")
    spi.close()
    gpio_line.close()
    exit(0)
    # ----------------------------------------------------------------------------------------------------------------


log_prefix = ''

if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        log(Colors.HI_RED, err)
        sys.exit(1)
    except KeyboardInterrupt:
        log(Colors.HI_RED, "interrupted")
        sys.exit(130)

