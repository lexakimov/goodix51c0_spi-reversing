import asyncio

import periphery
from periphery import CdevGPIO
from spidev import SpiDev


class Colors:
    END = "\033[0m"

    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"

    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"


def log(color, message):
    print(color, message, Colors.END, sep='')


def to_hex_string(byte_array: bytearray | bytes):
    return ' '.join('{:02X}'.format(num) for num in byte_array)


def to_utf_string(byte_array: bytearray | bytes):
    length = extract_length(byte_array)
    return f'[length: {length}] ' + bytearray(byte_array[3:]).decode('utf-8', errors='ignore')


def format_validity(is_valid: bool) -> str:
    return '🟢' if is_valid else '🔴'


def make_protocol_packet(packet_type: int, payload_length: int | list) -> bytearray:
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


async def interrupt_monitoring(gpio_line: periphery.CdevGPIO, ready_to_write_lock: asyncio.Lock):
    log(Colors.CYAN, "interrupt_monitoring started")
    ready_to_write_lock.release()
    i = 1
    while True:
        await asyncio.sleep(0.001)
        r = gpio_line.read()
        if r:
            log(Colors.CYAN, f"release read lock on iteration {i}")
            return True
        i += 1
        if i > 2000:
            log(Colors.RED + Colors.NEGATIVE, f"error: timeout {i}")
            return False


def is_checksum_valid(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    fact_sum = sum(packet[:-1])
    fact_sum_first_byte = fact_sum.to_bytes(10, byteorder="little")[0]
    return checksum == fact_sum_first_byte


def extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int


async def perform_write(spi: SpiDev, packet_type: int, payload: bytes | str | list[int]):
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    elif isinstance(payload, list):
        payload = bytearray(payload)

    log(Colors.LIGHT_PURPLE, "writing to device...")
    protocol_packet = make_protocol_packet(packet_type, len(payload))
    spi.writebytes(protocol_packet)
    log(Colors.LIGHT_PURPLE, f"\t- protocol packet sent: {to_hex_string(protocol_packet)}")
    spi.writebytes(payload)
    log(Colors.LIGHT_PURPLE, f"\t- payload packet sent: {to_hex_string(payload)} | {to_utf_string(payload)}")


async def perform_read(spi: SpiDev) -> list[int]:
    log(Colors.LIGHT_BLUE, "reading from device...")
    packet_1 = spi.readbytes(4)
    is_valid = is_checksum_valid(packet_1)
    log(Colors.LIGHT_BLUE,
        f"\t- received packet 1 {format_validity(is_valid) + Colors.BLUE} : {to_hex_string(packet_1)}")
    length = extract_length(packet_1)
    packet_2 = spi.readbytes(length)
    is_valid = is_checksum_valid(packet_2)
    log(Colors.LIGHT_BLUE,
        f"\t- received packet 2 {format_validity(is_valid) + Colors.BLUE} : {to_hex_string(packet_2)} | {to_utf_string(packet_2)}")
    return packet_2


async def perform_tx(spi: SpiDev, interrupt_line: CdevGPIO, packet_type: int, payload: bytes | str | list) -> list[int]:
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    elif isinstance(payload, list):
        payload = bytearray(payload)

    print("--------- perform write-read")
    ready_to_write_lock = asyncio.Lock()
    await ready_to_write_lock.acquire()
    print("latch created")

    ir_monitoring = asyncio.create_task(interrupt_monitoring(interrupt_line, ready_to_write_lock))
    await ready_to_write_lock.acquire()

    await perform_write(spi, packet_type, payload)

    print("waiting for gpio interrupt...")
    await ir_monitoring
    print("lock released, execution goes on")

    result = await perform_read(spi)
    print("--------- write-read done")
    return result


async def main():
    gpio_line = CdevGPIO('/dev/gpiochip0', 321, 'in', edge='both', bias='default')
    spi = SpiDev(1, 0)
    spi.max_speed_hz = 0x00989680  # 10 000 000
    # spi.mode = 0b00

    # reset_spi()
    # await asyncio.sleep(1)

    # possible values '00' or  [0x00] or bytearray([0x00])

    # await perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')
    #
    # await perform_write(spi, 0xa0, 'd5 03 00 00 00 d3')
    #
    # await perform_write(spi, 0xa0, '01 05 00 00 00 00 00 88')

    # ----------------------------------------------------------------------------------------------------------------
    # # get evk version: GF_HC460SEC_APP_14210

    await perform_tx(spi, gpio_line, 0xa0, 'a8 03 00 00 00 ff')
    await perform_read(spi)

    # ----------------------------------------------------------------------------------------------------------------
    # get mcu state

    #  write    9 -  0000: af 06 00 55 5c bf 00 00 86
    #   read    4 -  0000: a0 1a 00 ba
    #   read   26 -  0000: ae 17 00  [ 04 00 30 00 00 00 00 00 20 00 00 00 00 01 00 00 04 25 02 00 00 00 ] 65

    #  0x04003000000000002000000000010000042502000000
    #  version:4
    #  isPOVImageValid:0
    #  isTlsConnected:0
    #  isTlsUsed:0
    #  isLocked:0
    #  availImgCnt:0
    #  povImgCnt:3
    #  sensor_data_int_timeout_count:0
    #  image_crc_fail_count:0
    #  povTouchAccidentCnt:0x0
    #  readChipIDCnt:0
    #  sensorExceptionFlag:0
    #  sensorUnexpectedIntCnt:0
    #  to_master_timeout_count:0
    #  psk_len:32
    #  psk_check_fail:0
    #  psk_write_fail:0
    #  ec_falling_count:0
    #  system_up_stop_cnt:0
    #  system_down_pov_stop_cnt:0
    #  system_up_cleared_pov_count:0
    #  pov_wake_by_fp:1
    #  pov_wake_by_ec:0
    #  pov_procedure:0x0
    #  config_down_flag:0
    #  sensor_chip_id:0x2504
    #  sensor_type:2
    #  pov_capture_count:0
    #  normal_capture_count:0
    #  otp_mcu_check_status:0x0
    await perform_tx(spi, gpio_line, 0xa0, 'af 06 00 55 5c bf 00 00 86')
    # - received packet 1 🟢 : A0 1A 00 BA
    # - received packet 2 🔴 : AE 17 00 04 00 30 00 00 00 00 03 20 00 02 00 00 01 00 00 04 25 02 00 00 00 60
    # ----------------------------------------------------------------------------------------------------------------

    spi.close()
    gpio_line.close()


if __name__ == "__main__":
    asyncio.run(main())
