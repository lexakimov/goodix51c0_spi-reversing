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

log_frames = True
log_frames_width = 240
log_packet_max_length = 200


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


def to_bytes(payload: bytes | str | list[int]) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, str):
        return bytes.fromhex(payload.replace(" ", ""))
    if isinstance(payload, list):
        return bytearray(payload)
    else:
        raise RuntimeError(f"unhandled type: {type(payload)}")


def make_header_packet(packet_type: int, payload_length: int) -> bytearray:
    header_packet = bytearray([packet_type]) + payload_length.to_bytes(2, 'little')
    sum_int = 0x00
    for b in header_packet:
        sum_int = (sum_int + b) & 0xFF
    checksum: bytes = sum_int.to_bytes()
    header_packet += checksum

    return header_packet


def make_payload_packet(packet_type: int, data: bytes | str | list[int]):
    data = to_bytes(data)
    payload = bytes((packet_type,))
    target_len = len(data) + 1  # includes checksum byte
    payload += struct.pack("<h", target_len)
    payload += data
    checksum = 0xaa - sum(payload) & 0xff
    payload += bytes((checksum,))
    return payload


def calculate_checksum(packet: list[int] | bytes) -> int:
    return 0xaa - sum(packet) & 0xff


def calculate_checksum_for_mcu_timestamp(packet: list[int] | bytes) -> int:
    return (0xaa - sum(packet) & 0xff) + 1


def is_header_packet_checksum_valid(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    fact_sum = sum(packet[:-1]) & 0xff
    return checksum == fact_sum


def is_payload_packet_checksum_valid(packet: bytes | list[int] | bytearray):
    checksum = packet[-1]
    if checksum == 0x88:
        return None
    fact_sum = calculate_checksum(packet[:-1])
    return checksum == fact_sum


def extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int


def perform_read(is_ack=False) -> list[int]:
    logs_color = Colors.GREEN if is_ack else Colors.HI_BLUE
    log(logs_color, f"{'get ack' if is_ack else 'reading'} from device...")
    header_packet = spi.readbytes(4)
    is_valid = is_header_packet_checksum_valid(header_packet)
    validity = format_validity(is_valid)
    hex_cropped = crop(to_hex_string(header_packet), log_packet_max_length)
    log(logs_color, f"\t- packet received {validity} : {hex_cropped}")
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
    hex_cropped = crop(hex_string, log_packet_max_length)
    log(logs_color, f"\t- packet received {validity} : {hex_cropped}")

    if log_frames:
        packet_type_code = payload_packet[0]
        packet_type = types_by_code.get(packet_type_code, "UNKNOWN")
        type_hex = to_hex_string([packet_type_code, ])
        frame_rows = [f'[length:{payload_length:>4}] command: (0x{type_hex}) {packet_type}', hex_string]
        if packet_type_code == 0xA8:
            frame_rows.append(to_utf_string(payload_packet[3:-2]))
        print_frame(logs_color, '', log_frames_width, frame_rows)

    return payload_packet


def perform_write(packet_type: int, payload: bytes | str | list[int]):
    log(Colors.HI_PURPLE, "writing to device...")
    payload = to_bytes(payload)
    header_packet = make_header_packet(packet_type, len(payload))
    spi.writebytes(header_packet)
    is_1_valid = is_header_packet_checksum_valid(header_packet)
    validity = format_validity(is_1_valid)
    hex_string = crop(to_hex_string(header_packet), log_packet_max_length)
    log(Colors.HI_PURPLE, f"\t-     packet sent {validity} : {hex_string}")

    spi.writebytes(payload)
    is_2_valid = is_payload_packet_checksum_valid(payload)
    validity = format_validity(is_2_valid)
    hex_string = to_hex_string(payload)
    hex_cropped = crop(hex_string, log_packet_max_length)
    log(Colors.HI_PURPLE, f"\t-     packet sent {validity} : {hex_cropped}")

    if log_frames:
        payload_length = extract_length(header_packet)
        type_hex = to_hex_string([payload[0], ])
        packet_type = types_by_code.get(payload[0], "UNKNOWN")
        frame_rows = [f'[length:{payload_length:>4}] command: (0x{type_hex}) {packet_type}', hex_string]
        print_frame(Colors.HI_PURPLE, '', log_frames_width, frame_rows)


def interrupt_monitoring():
    current_state = None
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
    global spi
    global gpio_line
    global read_is_ready
    global read_is_done

    gpio_line = CdevGPIO('/dev/gpiochip0', 321, 'in', edge='both', bias='default')
    spi = SpiDev(1, 0)
    spi.max_speed_hz = 0x00989680  # 10 000 000
    spi.mode = 0b00

    read_is_ready = Lock()
    read_is_done = Lock()
    isr_thread = Thread(daemon=True, target=interrupt_monitoring, args=())
    isr_thread.start()
    manual_sleep(0.05)  # delay so that the interrupt thread has time to enter gpio_line.read_event()

    # ----------------------------------------------------------------------------------------------------------------
    reset_device()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ force unlock TLS ".ljust(log_frames_width, '━'))

    perform_write(0xa0, 'd5 03 00 00 00 d3')
    # not to wait for ack
    print()

    # ----------------------------------------------------------------------------------------------------------------
    get_evk_version()

    # ----------------------------------------------------------------------------------------------------------------
    get_mcu_state()

    # ----------------------------------------------------------------------------------------------------------------
    # Для отладки
    # read_bb010002()
    # read_bb020003()
    # if True: exit()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ write 0xbb010002 (encrypted PSK) && 0xbb010003 (PSK WB) ".ljust(log_frames_width, '━'))

    # flag (4 bytes) + length 332 (4 bytes) + host_psk_data (PSK, зашифрованный через DPAPI [324] + seed [8]) (332) = 340 bytes
    # длина должна быть кратна 4
    part_1 = '020001bb 4c010000 01000000d08c9ddf0115d1118c7a00c04fc297eb010000004c9ce67c50c6b04bb637cd1c725114ee04000000400000005400680069007300200069007300200074006800650020006400650073006300720069007000740069006f006e00200073007400720069006e0067002e0000001066000000010000200000006e4fa0f0c6eb2c205bf30919735f8e39ce6a751a66e135de92fdaa1c9f16df43000000000e8000000002000020000000be119bea5888c588612186d6e3326314be59647949eb5552b8d6c9c5ad0d981130000000cb4ab34e61d04580cacc208521685be96bbba73559878d70df9f85738ab57436d506a8d012f893387fe332fe3253f9bc400000005aa42ac11c54b4e8af8abc02e1cf9ebda823bd056513e6c5dc7de5a0baa3c5e357da67a34bd335f15429c6c449a3c45b3792f827d392e5f72a001530c0817a3a6be5a0cbeef03c0b'
    # это потом получаем в read 0xbb010002

    # flag (4 bytes) + length 102 (4 bytes) + PSK WB (который используется TLS, 102 bytes) + remainder (2 bytes) = 108 bytes
    # длина должна быть n*4+3 (3,7,11,15,19,23...)
    part_2 = '030001bb 66000000 fad1e5b87930265db0ed2544e3615056f619fc11e6a558f8e0d92003e479ff4102ff200000007ddcfcdba9e81b0c4815638d0305303b562e5f4014f40b9d76edf2755d9e5dbd8694b0508df786193deddfca4854fef93f68a5d5cfdeec1524290576fdad0c67'
    # от этого меняется ответ read 0xbb020003 (там возвращается SHA-256 хеш от 102 байт)

    # здесь зашифрован PSK: ed 75 57 81 4f fa 54 b3 3b 8a aa 72 4e 11 8e 17 de 06 34 6b 90 a2 1d 6a 56 e5 aa ac c7 a3 a8 f0

    # Затереть PSK. Вызовет повторную генерацию PSK и запись в Goodix_Cache.bin и в MCU
    # part_1 = '020001bb 10000000 00000000000000000000000000000000'
    # part_2 = '030001bb 10000000 00000000000000000000000000000000'

    parts = to_bytes(part_1 + part_2)

    # Если нужно, дополняем сообщение нулевыми байтами, чтобы длина стала кратна 4
    remainder = len(parts) % 4
    if remainder != 0:
        parts = parts.ljust(len(parts) + 4 - remainder, b'\x00')

    data = make_payload_packet(0xe0, parts)

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, data)
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    # > E0 03 00 00 51 76 - успешно
    acquire_then_release(read_is_done, 'read_is_done')

    manual_sleep(0.2)
    print()

    # ----------------------------------------------------------------------------------------------------------------
    # Экспериментально
    # write_bb010002('020001bb 1000 0000 44444444444444444444444444444455')
    # write_bb010003('030001bb 1000 0000 00000000000000000000000000000002')
    # if True: exit()

    # ----------------------------------------------------------------------------------------------------------------
    # Для отладки
    # read_bb010002() # (получаем 1:1 - то, что писали в 0xbb010002)
    # read_bb020003() # (получаем хеш - 32 байта, на основе того, что писали в 0xbb010003)
    # if True: exit()

    # ----------------------------------------------------------------------------------------------------------------
    # TODO: Не было в логах драйвера, догадался сам
    # log(Colors.HI_GREEN, "━━━ write 0xbb020003 ".ljust(log_frames_width, '━'))
    #
    # read_is_ready.acquire()
    # read_is_done.acquire()
    # # perform_write(0xa0, 'e0 09 00 03 00 02 bb 00 00 00 00 01')
    # perform_write(0xa0, make_payload_packet(0xe0, '03 00 02 bb 00 00 00 00'))
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read()  # get ack for cmd 0xe0, cfg flag 0x7
    # manual_sleep(0.05)
    # perform_read()
    # acquire_then_release(read_is_done, 'read_is_done')
    # print()

    # ----------------------------------------------------------------------------------------------------------------
    reset_sensor()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get MILAN_CHIPID ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, '82 06 00 00 00 00 04 00 1e')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0x82, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get OTP ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, 'a6 03 00 00 00 01')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xa6, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()

    # ----------------------------------------------------------------------------------------------------------------
    reset_sensor()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ setmode: idle ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, '70 03 00 14 00 23')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0x70, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    # > B0 03 00 70 07 80
    print()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ send Dac 0x380bb500b300b300 ".ljust(log_frames_width, '━'))
    # after that we can get image from sensor

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, '98 09 00 38 0b b5 00 b3 00 b3 00 ab')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0x98, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')

    # > 98 03 00 01 00 0E
    print()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ upload mcu config ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(
        0xa0,
        '90 E1 00 70 11 74 85 00 85 2C B1 18 C9 14 DD 00 DD 00 DD 00 BA 00 01 80 CA 00 04 00 84 00 15 B3 '
        '86 00 00 C4 88 00 00 BA 8A 00 00 B2 8C 00 00 AA 8E 00 00 C1 90 00 BB BB 92 00 B1 B1 94 00 00 A8 '
        '96 00 00 B6 98 00 00 00 9A 00 00 00 D2 00 00 00 D4 00 00 00 D6 00 00 00 D8 00 00 00 50 00 01 05 '
        'D0 00 00 00 70 00 00 00 72 00 78 56 74 00 34 12 20 00 10 40 5C 00 00 01 20 02 38 0B 36 02 B5 00 '
        '38 02 B3 00 3A 02 B3 00 2A 01 82 03 22 00 01 20 24 00 14 00 80 00 01 00 5C 00 00 01 56 00 04 20 '
        '58 00 03 02 32 00 0C 02 66 00 03 00 7C 00 00 58 82 00 80 1B 2A 01 08 00 54 00 10 01 62 00 04 03 '
        '64 00 19 00 66 00 03 00 7C 00 00 58 2A 01 08 00 52 00 08 00 54 00 00 01 66 00 03 00 7C 00 00 58 '
        '00 53 66 8F'
    )
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0x90, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')

    # > 90 03 00 01 00 16
    print()

    ####################################################### TLS #######################################################

    # ----------------------------------------------------------------------------------------------------------------
    # log(Colors.HI_GREEN, "━━━ get tls handshake package (client hello) ".ljust(log_frames_width, '━'))
    #
    # read_is_ready.acquire()
    # read_is_done.acquire()
    #
    # perform_write(0xa0, 'd1 03 00 00 00 d7')
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read()  # not to wait for ack
    # acquire_then_release(read_is_done, 'read_is_done')
    # print()

    # 16 03 03 00 2F 01 00 00 2B 03 03 2D F4 51 58 CF 8C B1 40 46 F6 B5 4B 29 31 03 47 04 5B 70 30 B4 5D FD 20 78 7F 8B 1A D8 59 29 50 00 00 04 00 A8 00 FF 01 00
    # 52          47          43

    # exit()

    # ----------------------------------------------------------------------------------------------------------------

    # отправляем пакет в ssl сервер (TLS-PSK-WITH-AES-128-GCM-SHA256)
    # поучаем ответ от ssl сервера, отправляем в MCU

    # ----------------------------------------------------------------------------------------------------------------
    # log(Colors.HI_GREEN, "━━━ tls 1 ".ljust(log_frames_width, '━'))
    #
    # perform_write(0xb0, '16 03 03 00 51 02 00 00 4d 03 03 9c 45 f7 ca 9a 9e b1 ec e4 3f d4 b4 4c 39 72 22 e6 7d 3c e8 '
    #                     '2b 66 50 80 57 46 a4 17 13 71 b7 8c 20 92 4f f3 83 b8 15 a9 20 19 0c 93 4a 20 4f f3 a7 1b fd '
    #                     '2d 40 03 cb 18 37 81 b9 6b ce 7c 04 b9 9e 00 a8 00 00 05 ff 01 00 01 00')
    # manual_sleep(0.1)
    #
    # perform_write(0xb0, '16 03 03 00 04 0e 00 00 00')
    # manual_sleep(0.1)
    #
    # perform_read()
    # manual_sleep(0.1)
    #
    # perform_read()
    # manual_sleep(0.1)
    #
    # perform_read()
    # manual_sleep(0.1)
    #
    #
    # perform_write(0xb0, '14 03 03 00 01 01')
    # manual_sleep(0.1)
    #
    # perform_write(0xb0, '16 03 03 00 28 00 00 00 00 00 00 00 00 ef 3e db fd 53 50 df e4 f2 8e 82 fd e8 8d a8 f7 1d 58 '
    #                     '8f 15 11 51 59 d5 01 68 40 84 2f 7b fd 76')
    # manual_sleep(0.1)
    #
    # perform_write(0xa0, 'd4 03 00 00 00 d3')
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    #
    # perform_write(0xa0, 'af 06 00 55 6e a7 00 00 8c')
    # # no ack
    # manual_sleep(0.1)
    #
    # perform_read()
    # manual_sleep(0.1)
    #
    #
    # perform_write(0xa0, '36 0f 00 09 01 00 00 00 00 00 00 00 00 00 00 00 00 5b')
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    #
    #
    # perform_write(0xa0, '50 03 00 01 00 56')
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    #
    # perform_write(0xa0, '36 0f 00 09 01 80 b0 80 c3 80 a5 80 b7 80 a7 80 b7 2e')
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    #
    # perform_write(0xa0, '82 06 00 00 82 00 02 00 9e')
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    # perform_read()
    # manual_sleep(0.1)
    # print()

    # ----------------------------------------------------------------------------------------------------------------
    # log(Colors.HI_GREEN, "━━━ get fdt base ".ljust(log_frames_width, '━'))
    #
    # read_is_ready.acquire()
    # read_is_done.acquire()
    #
    # perform_write(0xa0, '36 0f 00 09 01 00 00 00 00 00 00 00 00 00 00 00 00 5b')
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read()
    # manual_sleep(0.05)
    # perform_read()
    # acquire_then_release(read_is_done, 'read_is_done')
    # print()

    # ----------------------------------------------------------------------------------------------------------------
    # log(Colors.HI_GREEN, "━━━ get nav base ".ljust(log_frames_width, '━'))
    #
    # read_is_ready.acquire()
    # read_is_done.acquire()
    #
    # perform_write(0xa0, '50 03 00 01 00 56')
    # acquire_then_release(read_is_ready, 'read_is_ready')
    # perform_read()
    # manual_sleep(0.05)
    # perform_read()
    # acquire_then_release(read_is_done, 'read_is_done')
    # print()

    # ----------------------------------------------------------------------------------------------------------------
    log(Colors.HI_GREEN, "━━━ get image ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, '20 03 00 01 00 86')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0x20, cfg flag 0x1
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()

    acquire_then_release(read_is_ready, 'read_is_ready')
    image_packet = perform_read()
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


def reset_device():
    log(Colors.RED, "reset device...")
    read_is_ready.acquire()
    read_is_done.acquire()

    gpio_reset = CdevGPIO('/dev/gpiochip0', 140, 'out', label='goodix-fp-reset')
    for i in (1, 0):
        gpio_reset.write(bool(i))
        sleep(0.01)
    gpio_reset.close()

    read_is_done.acquire()
    read_is_done.release()
    read_is_ready.acquire()
    read_is_ready.release()
    manual_sleep(0.15)
    log(Colors.RED, "reset done")


def reset_sensor():
    log(Colors.HI_GREEN, "━━━ reset sensor ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, 'a2 03 00 01 14 f0')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xa2, cfg flag 0x7
    acquire_then_release(read_is_done, 'read_is_done')

    read_is_ready.acquire()
    read_is_done.acquire()
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()


def get_mcu_state():
    log(Colors.HI_GREEN, "━━━ get mcu state ".ljust(log_frames_width, '━'))

    log(Colors.HI_YELLOW, "required for get mcu state, upload MCU config")
    perform_write(0xa0, '01 05 00 00 00 00 00 88')
    # not to wait for ack
    manual_sleep(0.05)
    # perform_write(0xa0, '97 03 00 01 01 0f')
    # # not to wait for ack
    print()

    read_is_ready.acquire()
    read_is_done.acquire()

    now = datetime.now()
    now_milliseconds = now.second * 1000 + now.microsecond // 1000
    millis = to_hex_string(now_milliseconds.to_bytes(2, 'little'))
    get_mcu_state_payload = bytes.fromhex(f'af 06 00 55 {millis} 00 00'.replace(' ', ''))
    get_mcu_state_payload += calculate_checksum_for_mcu_timestamp(get_mcu_state_payload).to_bytes()
    # get_mcu_state_payload = bytes.fromhex(f'af 06 00 55 5c bf 00 00 86')

    perform_write(0xa0, get_mcu_state_payload)
    # not to wait for ack
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()


def get_evk_version():
    log(Colors.HI_GREEN, "━━━ get evk version ".ljust(log_frames_width, '━'))

    log(Colors.HI_YELLOW, "required for get evk version")
    perform_write(0xa0, '01 05 00 00 00 00 00 88')
    # not to wait for ack
    manual_sleep(0.05)
    print()

    read_is_ready.acquire()
    read_is_done.acquire()

    perform_write(0xa0, 'a8 03 00 00 00 ff')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xa8, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()


def write_bb010002(payload):
    """
    Записать PSK, зашифрованный через DPAPI
    """
    # ЭТО РАБОТАЕТ
    # Не было в логах драйвера, догадался сам.
    log(Colors.HI_GREEN, "━━━ write 0xbb010002 (encrypted PSK) ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    data = make_payload_packet(0xe0, payload)

    perform_write(0xa0, data)
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read()  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()


def write_bb010003(payload):
    """
    Записать PSK WB
    """
    # ЭТО РАБОТАЕТ
    # Не было в логах драйвера, догадался сам.
    log(Colors.HI_GREEN, "━━━ write 0xbb010003 (PSK WB) ".ljust(log_frames_width, '━'))

    read_is_ready.acquire()
    read_is_done.acquire()

    # значение из примеров с USB
    # payload = '030001bb 60000000 ec35ae3abb45ed3f12c4751f1e5c2cc05b3c5452e9104d9f2a3118644f37a04b6fd66b1d97cf80f1345f76c84f03ff30bb51bf308f2a9875c41e6592cd2a2f9e60809b17b5316037b69bb2fa5d4c8ac31edb3394046ec06bbdacc57da6a756c5'
    data = make_payload_packet(0xe0, payload)

    perform_write(0xa0, data)
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read()  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')

    # > E0 03 00 00 03 C4
    print()

def read_bb010002():
    """
    Прочитать PSK, зашифрованный через DPAPI
    """
    log(Colors.HI_GREEN, "━━━ read 0xbb010002 (encrypted PSK) ".ljust(log_frames_width, '━'))
    read_is_ready.acquire()
    read_is_done.acquire()
    perform_write(0xa0, 'e4 09 00 02 00 01 bb 00 00 00 00 ff')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    # ответ [length: 345] если PSK задан, либо E4 03 00 01 51 71 если PSK не задан
    acquire_then_release(read_is_done, 'read_is_done')
    print()


def read_bb020003():
    """
    Прочитать SHA-256 хеш ранее заданного PSK WB
    """
    log(Colors.HI_GREEN, "━━━ read 0xbb020003 (PSK WB hash) ".ljust(log_frames_width, '━'))
    read_is_ready.acquire()
    read_is_done.acquire()
    perform_write(0xa0, 'e4 09 00 03 00 02 bb 00 00 00 00 fd')
    acquire_then_release(read_is_ready, 'read_is_ready')
    perform_read(True)  # get ack for cmd 0xe4, cfg flag 0x7
    manual_sleep(0.05)
    perform_read()
    acquire_then_release(read_is_done, 'read_is_done')
    print()


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
