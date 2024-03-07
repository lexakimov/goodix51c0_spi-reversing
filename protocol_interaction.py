import struct
import sys
import time
from datetime import datetime
from threading import Lock, Thread
from time import sleep

from periphery import CdevGPIO
from periphery.gpio import GPIOError
from spidev import SpiDev

from image_decode import show_image
from packet_parsing import types_by_code
from util_fmt import Colors, log, to_hex_string, format_validity, print_frame, crop, to_utf_string

log_isr_events = False
log_synchronization_events = False
log_manual_sleeps = False

hex_string_length_limit = 80


def manual_sleep(duration):
    if log_manual_sleeps:
        log(Colors.HI_YELLOW, f"sleep for {duration} second(s)...")
    sleep(duration)
    if log_manual_sleeps:
        log(Colors.HI_YELLOW, "resume")


def acquire_then_release(lock, label):
    if log_synchronization_events:
        log('\033[48;5;0m', f"wait for {label}")
    if not lock.acquire(timeout=3):
        raise TimeoutError()
    if log_synchronization_events:
        log('\033[48;5;0m', f"{label} received. resume")
    lock.release()


def make_header_packet(packet_type: int, payload_length: int) -> bytearray:
    header_packet = bytearray([packet_type]) + payload_length.to_bytes(2, 'little')
    sum_int = 0x00
    for b in header_packet:
        sum_int = (sum_int + b) & 0xFF
    checksum: bytes = sum_int.to_bytes()
    header_packet += checksum

    return header_packet


def make_payload_packet(packet_type: int, data):
    payload = bytes((packet_type,))
    target_len = len(data) + 1  # includes checksum byte
    payload += struct.pack("<h", target_len)
    payload += data
    checksum = 0xaa - sum(payload) & 0xff
    payload += bytes((checksum,))
    return payload


def calculate_checksum_for_mcu_timestamp(packet: list[int] | bytes) -> int:
    return (0xaa - sum(packet) & 0xff) + 1


def is_header_packet_checksum_valid(packet: list[int] | bytearray) -> bool:
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


def reset_spi():
    gpio_reset = CdevGPIO('/dev/gpiochip0', 140, 'out', label='goodix-fp-reset')
    for i in (1, 0):
        gpio_reset.write(bool(i))
        sleep(0.01)
    gpio_reset.close()


def perform_read(spi: SpiDev) -> list[int]:
    log(Colors.HI_BLUE, "reading from device...")
    header_packet = spi.readbytes(4)
    is_valid = is_header_packet_checksum_valid(header_packet)
    validity = format_validity(is_valid)
    hex_cropped = crop(to_hex_string(header_packet), hex_string_length_limit)
    log(Colors.HI_BLUE, f"\t- packet received {validity} : {hex_cropped}")
    payload_length = extract_length(header_packet)

    if header_packet == [0, 0, 0, 0]:
        raise RuntimeError('read error: 00 00 00 00 bytes are received')
    if payload_length == 0xFFFF:
        raise RuntimeError('read error: FF bytes are received')

    payload_packet = list()
    bytes_left = payload_length
    while bytes_left > 0:
        chunk = spi.readbytes(bytes_left)
        payload_packet += chunk
        bytes_left -= len(chunk)

    is_valid = is_payload_packet_checksum_valid(payload_packet)
    validity = format_validity(is_valid)
    hex_string = to_hex_string(payload_packet)
    hex_cropped = crop(hex_string, hex_string_length_limit)
    log(Colors.HI_BLUE, f"\t- packet received {validity} : {hex_cropped}")

    packet_type_code = payload_packet[0]
    packet_type = types_by_code.get(packet_type_code, "UNKNOWN")
    type_hex = to_hex_string([packet_type_code, ])
    frame_rows = [f'[length:{payload_length:>4}] command: (0x{type_hex}) {packet_type}', hex_string]
    if packet_type_code == 0xA8:
        frame_rows.append(to_utf_string(payload_packet[3:-2]))
    print_frame(Colors.HI_BLUE, '', 120, frame_rows)

    return payload_packet


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

    log(Colors.HI_PURPLE, "writing to device...")
    header_packet = make_header_packet(packet_type, len(payload))
    spi.writebytes(header_packet)
    is_1_valid = is_header_packet_checksum_valid(header_packet)
    validity = format_validity(is_1_valid)
    hex_string = crop(to_hex_string(header_packet), hex_string_length_limit)
    log(Colors.HI_PURPLE, f"\t-     packet sent {validity} : {hex_string}")

    spi.writebytes(payload)
    is_2_valid = is_payload_packet_checksum_valid(payload)
    validity = format_validity(is_2_valid)
    hex_string = crop(to_hex_string(payload), hex_string_length_limit)
    log(Colors.HI_PURPLE, f"\t-     packet sent {validity} : {hex_string}")

    payload_length = extract_length(header_packet)
    type_hex = to_hex_string([payload[0], ])
    packet_type = types_by_code.get(payload[0], "UNKNOWN")
    print_frame(Colors.HI_PURPLE, '', 120, [f'[length:{payload_length:>4}] command: (0x{type_hex}) {packet_type}', ])


def interrupt_monitoring(gpio_line: CdevGPIO, read_is_ready: Lock, read_is_done: Lock):
    is_high = False
    i = 0
    last_ts = time.time_ns()
    if log_isr_events:
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
            if log_isr_events:
                log(Colors.CYAN, f"gpio interrupt: rising  [iteration {i}] {passed_ms}ms) - data ready to read")
            if read_is_ready.locked():
                read_is_ready.release()
            else:
                if log_isr_events:
                    log(Colors.RED, "trying to release unlocked read_is_ready")
            is_high = True
            last_ts = event_time
            i = 0

        # if event_edge == 'falling' and is_high:
        if not current_state and is_high:
            passed_ms = int((event_time - last_ts) / 1000000)
            if log_isr_events:
                log(Colors.CYAN, f"gpio interrupt: falling [iteration {i}] {passed_ms}ms) - reading completed")
            if read_is_done.locked():
                read_is_done.release()
            else:
                if log_isr_events:
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
    isr_thread = Thread(daemon=True, target=interrupt_monitoring, args=(gpio_line, read_is_ready, read_is_done))
    isr_thread.start()
    manual_sleep(0.05)  # delay so that the interrupt thread has time to enter gpio_line.read_event()

    # ----------------------------------------------------------------------------------------------------------------
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
    # not to wait for ack

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ force unlock TLS ".ljust(120, '━'))
    perform_write(spi, 0xa0, 'd5 03 00 00 00 d3')
    # not to wait for ack
    manual_sleep(0.1)  # если после записи нет прерывания надо подождать

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get evk version ".ljust(120, '━'))

    perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    # not to wait for ack
    manual_sleep(0.05)

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a8 03 00 00 00 ff')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xa8, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get mcu state ".ljust(120, '━'))

    # perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    # # not to wait for ack
    # perform_write(spi, 0xa0, '97 03 00 01 01 0f')
    # # not to wait for ack

    read_is_ready.acquire()
    read_is_done.acquire()

    now = datetime.now()
    now_milliseconds = now.second * 1000 + now.microsecond // 1000
    millis = to_hex_string(now_milliseconds.to_bytes(2, 'little'))
    get_mcu_state_payload = bytes.fromhex(f'af 06 00 55 {millis} 00 00'.replace(' ', ''))
    get_mcu_state_payload += calculate_checksum_for_mcu_timestamp(get_mcu_state_payload).to_bytes()
    perform_write(spi, 0xa0, get_mcu_state_payload)
    # perform_write(spi, 0xa0, 'af 06 00 55 5c bf 00 00 86')
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

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ write (0xbb010002) ".ljust(120, '━'))
    # можно изменить текущий psk

    # fromhex = bytes.fromhex(f"020001bb 0e00 0000 4141414142424242434343434444".replace(" ", ""))
    str_1 = '020001bb'
    str_2 = '4c01000001000000d08c9ddf0115d1118c7a00c04fc297eb010000004c9ce67c50c6b04bb637cd1c725114ee04000000400000005400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e0000001066000000010000200000006e4fa0f0c6eb2c205bf30919735f8e39ce6a751a66e135de92fdaa1c9f16df43000000000e8000000002000020000000be119bea5888c588612186d6e3326314be59647949eb5552b8d6c9c5ad0d981130000000cb4ab34e61d04580cacc208521685be96bbba73559878d70df9f85738ab57436d506a8d012f893387fe332fe3253f9bc400000005aa42ac11c54b4e8af8abc02e1cf9ebda823bd056513e6c5dc7de5a0baa3c5e357da67a34bd335f15429c6c449a3c45b3792f827d392e5f72a001530c0817a3a6be5a0cbeef03c0b'
    str_3 = '030001bb'
    str_4 = '66000000fad1e5b87930265db0ed2544e3615056f619fc11e6a558f8e0d92003e479ff4102ff200000007ddcfcdba9e81b0c4815638d0305303b562e5f4014f40b9d76edf2755d9e5dbd8694b0508df786193deddfca4854fef93f68a5d5cfdeec1524290576fdad0c670000'
    fromhex = bytes.fromhex(f"{str_1}{str_2}{str_3}{str_4}".replace(" ", ""))

    data = make_payload_packet(0xe0, fromhex)

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, data)
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    manual_sleep(0.2)

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ Write PSK (0xbb010003) ".ljust(120, '━'))

    # read_is_ready.acquire()
    # read_is_done.acquire()
    #
    # PSK_WB = 'ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5'
    # fromhex = bytes.fromhex(f"030001bb 6000 0000 {PSK_WB}".replace(" ", ""))
    # data = make_payload_packet(0xe0, fromhex)
    #
    # perform_write(spi, 0xa0, data)
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read(spi)  # get ack for cmd 0xe4, cfg flag 0x7
    # manual_sleep(0.05)
    # perform_read(spi)
    # acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------

    # TODO поставить в IDA остановки на "1.seal psk", "Random sequence generated"
    # попытаться выцепить psk + зашифрованный psk. и pmk

    # [production_psk_process:01953]    Goodix>>> . write psk to mcu (total times:2)
    # [production_psk_process:01956]    Goodix>>> write psk to mcu (times:1)
    # [generate_entropy2:02082]         Goodix>>> random not exist or invalid, generate new data
    # [generate_rand:00185]             Goodix>>> CryptAcquireContext succeeded
    # [generate_rand:00210]             Goodix>>> Random sequence generated: 8
    # [generate_entropy2:02094]         Goodix>>> generate rootkey
    # [production_write_key:02183]      Goodix>>> 0.generate random psk
    # [generate_rand:00185]             Goodix>>> CryptAcquireContext succeeded
    # [generate_rand:00210]             Goodix>>> Random sequence generated: 32
    # [production_write_key:02193]      Goodix>>> 1.seal psk
    # [gf_seal_data:00034]              Goodix>>> inbuf_len 32, entropy_len 48, len_out 2048
    # [gf_seal_data:00066]              Goodix>>> The encryption phase worked, 32, 324

    # [production_write_key:02203]      Goodix>>> seal psk, ret 0x0 length before 32, length after:324
    # [production_write_key:02211]      Goodix>>> 2.process encrypted psk
    # [production_write_key:02222]      Goodix>>> process ret 0x0 type 0xbb010003, length before 32, length after:102
    # [production_write_key:02231]      Goodix>>> 3.write to mcu
    # [production_write_key:02256]      Goodix>>> data_to_mcu_len 450 bytes, remainder4 is 2 bytes
    # [production_write_key:02260]      Goodix>>> remainder4 is not 0, add 2 bytes then finally data_to_mcu_len 452 bytes
    # [production_write_key:02276]      Goodix>>> write data: length 452, type 0xbb010002
    # [production_write_mcu:02606]      Goodix>>> Entry, length 452
    # [clean_psk_cache:02662]           Goodix>>> Will Clear the cache buffer.
    # [production_write_mcu:02616]      Goodix>>> 1.SpiSendDataToDeviceLock
    # [SpiSendDataToDevice:03392]       Goodix>>> cmd0-cmd1-Len-ackt-ec:0xe-0-0x1c4-1000-0
    #  write    4 -  0000: a0 c8 01 69
    #  write  456 -  0000: e0 c5 01 02 00 01 bb 4c 01 00 00 01 00 00 00 d0
    #  write  456 -  0010: 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb 01
    #  write  456 -  0020: 00 00 00 4c 9c e6 7c 50 c6 b0 4b b6 37 cd 1c 72
    #  write  456 -  0030: 51 14 ee 04 00 00 00 40 00 00 00 54 00 68 00 69
    #  write  456 -  0040: 00 73 00 20 00 69 00 73 00 20 00 74 00 68 00 65
    #  write  456 -  0050: 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70
    #  write  456 -  0060: 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00 72
    #  write  456 -  0070: 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00 00
    #  write  456 -  0080: 01 00 00 20 00 00 00 6e 4f a0 f0 c6 eb 2c 20 5b
    #  write  456 -  0090: f3 09 19 73 5f 8e 39 ce 6a 75 1a 66 e1 35 de 92
    #  write  456 -  00a0: fd aa 1c 9f 16 df 43 00 00 00 00 0e 80 00 00 00
    #  write  456 -  00b0: 02 00 00 20 00 00 00 be 11 9b ea 58 88 c5 88 61
    #  write  456 -  00c0: 21 86 d6 e3 32 63 14 be 59 64 79 49 eb 55 52 b8
    #  write  456 -  00d0: d6 c9 c5 ad 0d 98 11 30 00 00 00 cb 4a b3 4e 61
    #  write  456 -  00e0: d0 45 80 ca cc 20 85 21 68 5b e9 6b bb a7 35 59
    #  write  456 -  00f0: 87 8d 70 df 9f 85 73 8a b5 74 36 d5 06 a8 d0 12
    #  write  456 -  0100: f8 93 38 7f e3 32 fe 32 53 f9 bc 40 00 00 00 5a
    #  write  456 -  0110: a4 2a c1 1c 54 b4 e8 af 8a bc 02 e1 cf 9e bd a8
    #  write  456 -  0120: 23 bd 05 65 13 e6 c5 dc 7d e5 a0 ba a3 c5 e3 57
    #  write  456 -  0130: da 67 a3 4b d3 35 f1 54 29 c6 c4 49 a3 c4 5b 37
    #  write  456 -  0140: 92 f8 27 d3 92 e5 f7 2a 00 15 30 c0 81 7a 3a 6b
    #  write  456 -  0150: e5 a0 cb ee f0 3c 0b 03 00 01 bb 66 00 00 00 fa
    #  write  456 -  0160: d1 e5 b8 79 30 26 5d b0 ed 25 44 e3 61 50 56 f6
    #  write  456 -  0170: 19 fc 11 e6 a5 58 f8 e0 d9 20 03 e4 79 ff 41 02
    #  write  456 -  0180: ff 20 00 00 00 7d dc fc db a9 e8 1b 0c 48 15 63
    #  write  456 -  0190: 8d 03 05 30 3b 56 2e 5f 40 14 f4 0b 9d 76 ed f2
    #  write  456 -  01a0: 75 5d 9e 5d bd 86 94 b0 50 8d f7 86 19 3d ed df
    #  write  456 -  01b0: ca 48 54 fe f9 3f 68 a5 d5 cf de ec 15 24 29 05
    #  write  456 -  01c0: 76 fd ad 0c 67 00 00 ad
    #
    # ---------------------------------------------
    # полный пакет [длина 456]
    #
    # e0
    # c5 01 			[указание полезной длины + контрольная сумма = 453]
    # 02 00 01 bb 	[specific data_type 0xbb010002 (был указан в запросе)]
    # 4c 01 			   [длина блока 0xbb010002 (332)]
    # 00 00
    #
    # [далее host_psk_data (содержимое Goodix_Cache.bin), длина 332]
    #
    # 01 00 00 00
    # d0 8c 9d df 01 15 d1 11 8c 7a 00 c0 4f c2 97 eb
    # 01 00 00 00 4c 9c e6 7c 50 c6 b0 4b b6 37 cd 1c
    # 72 51 14 ee 04 00 00 00 40 00 00 00 54 00 68 00
    # 69 00 73 00 20 00 69 00 73 00 20 00 74 00 68 00
    # 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00
    # 70 00 74 00 69 00 6f 00 6e 00 20 00 73 00 74 00
    # 72 00 69 00 6e 00 67 00 2e 00 00 00 10 66 00 00
    # 00 01 00 00 20 00 00 00 6e 4f a0 f0 c6 eb 2c 20
    # 5b f3 09 19 73 5f 8e 39 ce 6a 75 1a 66 e1 35 de
    # 92 fd aa 1c 9f 16 df 43 00 00 00 00 0e 80 00 00
    # 00 02 00 00 20 00 00 00 be 11 9b ea 58 88 c5 88
    # 61 21 86 d6 e3 32 63 14 be 59 64 79 49 eb 55 52
    # b8 d6 c9 c5 ad 0d 98 11 30 00 00 00 cb 4a b3 4e
    # 61 d0 45 80 ca cc 20 85 21 68 5b e9 6b bb a7 35
    # 59 87 8d 70 df 9f 85 73 8a b5 74 36 d5 06 a8 d0
    # 12 f8 93 38 7f e3 32 fe 32 53 f9 bc 40 00 00 00
    # 5a a4 2a c1 1c 54 b4 e8 af 8a bc 02 e1 cf 9e bd
    # a8 23 bd 05 65 13 e6 c5 dc 7d e5 a0 ba a3 c5 e3
    # 57 da 67 a3 4b d3 35 f1 54 29 c6 c4 49 a3 c4 5b
    # 37 92 f8 27 d3 92 e5 f7 2a 00 15 30 c0 81 7a 3a
    # 6b e5 a0 cb ee f0 3c 0b
    #
    # 03 00 01 bb 	[specific data_type 0xbb010003 (был указан в запросе)]
    # 66 00 			   [длина блока 0xbb010003 (102)]
    # 00 00
    #
    # [102]
    #
    # fa d1 e5 b8 79 30 26 5d b0 ed 25 44 e3 61 50 56
    # f6 19 fc 11 e6 a5 58 f8 e0 d9 20 03 e4 79 ff 41
    # 02 ff 20 00 00 00 7d dc fc db a9 e8 1b 0c 48 15
    # 63 8d 03 05 30 3b 56 2e 5f 40 14 f4 0b 9d 76 ed
    # f2 75 5d 9e 5d bd 86 94 b0 50 8d f7 86 19 3d ed
    # df ca 48 54 fe f9 3f 68 a5 d5 cf de ec 15 24 29
    # 05 76 fd ad 0c 67
    #
    # 00 00
    # ad 				[контрольная сумма]
    # ---------------------------------------------
    #
    # [data_from_device:04920]  Goodix>>> recvd data cmd-len: 0xb0-3
    # [get_msg_data:06260]      Goodix>>> get ack for cmd 0xe0, cfg flag 0x7
    #   read    4 -  0000: a0 06 00 a6
    #   read    6 -  0000: b0 03 00 e0 07 10
    # [get_msg_data:06277]      Goodix>>> MCU has no config
    # [data_from_device:04920]  Goodix>>> recvd data cmd-len: 0xe0-3
    # [data_from_device:05201]  Goodix>>> --- Received production response
    # [data_from_device:05205]  Goodix>>> production response pure data length=2
    #   read    4 -  0000: a0 06 00 a6
    #   read    6 -  0000: e0 03 00 00 51 76

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ read host psk hash (0xbb010002) ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'e4 09 00 02 00 01 bb 00 00 00 00 ff')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ read psk mcu hash (0xbb020003) ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'e4 09 00 03 00 02 bb 00 00 00 00 fd')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # TODO write 0xbb020003
    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ reset sensor ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a2 03 00 01 14 f0')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xa2, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get MILAN_CHIPID ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '82 06 00 00 00 00 04 00 1e')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0x82, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get OTP ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a6 03 00 00 00 01')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xa6, cfg flag 0x7
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

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ reset sensor ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, 'a2 03 00 01 14 f0')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0xa2, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ setmode: idle ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '70 03 00 14 00 23')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0x70, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ send Dac 0x380bb500b300b300 ".ljust(120, '━'))
    # after that we can get image from sensor

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '98 09 00 38 0b b5 00 b3 00 b3 00 ab')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0x98, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ upload mcu config ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '90 E1 00 70 11 74 85 00 85 2C B1 18 C9 14 DD 00 DD 00 DD 00 BA 00 01 80 CA 00 04 00 84 '
                             '00 15 B3 86 00 00 C4 88 00 00 BA 8A 00 00 B2 8C 00 00 AA 8E 00 00 C1 90 00 BB BB 92 00 '
                             'B1 B1 94 00 00 A8 96 00 00 B6 98 00 00 00 9A 00 00 00 D2 00 00 00 D4 00 00 00 D6 00 00 '
                             '00 D8 00 00 00 50 00 01 05 D0 00 00 00 70 00 00 00 72 00 78 56 74 00 34 12 20 00 10 40 '
                             '5C 00 00 01 20 02 38 0B 36 02 B5 00 38 02 B3 00 3A 02 B3 00 2A 01 82 03 22 00 01 20 24 '
                             '00 14 00 80 00 01 00 5C 00 00 01 56 00 04 20 58 00 03 02 32 00 0C 02 66 00 03 00 7C 00 '
                             '00 58 82 00 80 1B 2A 01 08 00 54 00 10 01 62 00 04 03 64 00 19 00 66 00 03 00 7C 00 00 '
                             '58 2A 01 08 00 52 00 08 00 54 00 00 01 66 00 03 00 7C 00 00 58 00 53 66 8F')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0x90, cfg flag 0x7
    manual_sleep(0.05)
    perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get tls handshake package ".ljust(120, '━'))

    # read_is_ready.acquire()
    # read_is_done.acquire()
    #
    # perform_write(spi, 0xa0, 'd1 03 00 00 00 d7')
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read(spi)  # not to wait for ack
    # acquire_then_release(read_is_done, 'read_is_done')

    print()
    # ----------------------------------------------------------------------------------------------------------------

    # отправляем пакет в ssl сервер (TLS-PSK-WITH-AES-128-GCM-SHA256)
    # поучаем ответ от ssl сервера, отправляем сканеру

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get image ".ljust(120, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(spi, 0xa0, '20 03 00 01 00 86')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(spi)  # get ack for cmd 0x20, cfg flag 0x1
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()

    acquire_then_release(read_is_ready, 'read_is_ready')
    image_packet = perform_read(spi)
    acquire_then_release(read_is_done, 'read_is_done')

    # log(Colors.ITALIC, "image packet bytes:\n" + ' '.join('{:02X}'.format(num) for num in image_packet))
    show_image(image_packet)

    print()
    # ----------------------------------------------------------------------------------------------------------------
    # manual_sleep(3)
    log(Colors.NEGATIVE, "closing")
    spi.close()
    gpio_line.close()
    exit(0)
    # ----------------------------------------------------------------------------------------------------------------


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as err:
        log(Colors.HI_RED, err)
        sys.exit(1)
    except TimeoutError as err:
        log(Colors.HI_RED, "timeout")
        sys.exit(1)
    except KeyboardInterrupt:
        log(Colors.HI_RED, "interrupted")
        sys.exit(130)
