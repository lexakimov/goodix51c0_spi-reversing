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


def format_checksum(is_valid: bool) -> str:
    if is_valid:
        return Colors.GREEN + '[ valid ]' + Colors.END
    else:
        return Colors.RED + '[invalid]' + Colors.END


def make_cmd_packet(cmd: int, length: int | list) -> bytearray:
    """
    cmd
        command 0xA0
    payload
        bytes of payload
    """
    payload_length: bytes = length.to_bytes(2, 'little')
    command_packet = bytearray([cmd]) + payload_length
    checksum: bytes = sum(command_packet).to_bytes()
    command_packet += checksum

    return command_packet


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
        if i > 5000:
            log(Colors.CYAN, f"error: timeout {i}")
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


async def perform_write(spi: SpiDev, cmd: int, payload: bytes):
    log(Colors.LIGHT_PURPLE, "writing to device...")
    cmd_packet = make_cmd_packet(cmd, len(payload))
    spi.writebytes(cmd_packet)
    log(Colors.LIGHT_PURPLE, f"\t- command packet sent: {to_hex_string(cmd_packet)}")
    spi.writebytes(payload)
    log(Colors.LIGHT_PURPLE, f"\t- payload packet sent: {to_hex_string(payload)} | {to_utf_string(payload)}")


async def perform_read(spi: SpiDev) -> list[int]:
    log(Colors.LIGHT_BLUE, "reading from device...")
    packet_1 = spi.readbytes(4)
    is_valid = is_checksum_valid(packet_1)
    log(Colors.LIGHT_BLUE,
        f"\t- received packet 1 {format_checksum(is_valid) + Colors.BLUE} : {to_hex_string(packet_1)}")
    length = extract_length(packet_1)
    packet_2 = spi.readbytes(length)
    is_valid = is_checksum_valid(packet_2)
    log(Colors.LIGHT_BLUE,
        f"\t- received packet 2 {format_checksum(is_valid) + Colors.BLUE} : {to_hex_string(packet_2)} | {to_utf_string(packet_2)}")
    return packet_2


async def perform_tx(spi: SpiDev, interrupt_line: CdevGPIO, cmd: int, payload: bytes) -> list[int]:
    print("--------- perform write-read")
    ready_to_write_lock = asyncio.Lock()
    await ready_to_write_lock.acquire()
    print("latch created")

    ir_monitoring = asyncio.create_task(interrupt_monitoring(interrupt_line, ready_to_write_lock))
    await ready_to_write_lock.acquire()

    await perform_write(spi, cmd, payload)

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
    await asyncio.sleep(0.1)

    await perform_write(spi, 0xa0, bytearray([0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88]))
    await asyncio.sleep(0.1)

    await perform_write(spi, 0xa0, bytearray([0xd5, 0x03, 0x00, 0x00, 0x00, 0xd3]))
    await asyncio.sleep(0.1)

    await perform_write(spi, 0xa0, bytearray([0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88]))
    await asyncio.sleep(0.1)

    ready_to_write = asyncio.Lock()
    await ready_to_write.acquire()
    print("latch created")
    ir_monitoring = asyncio.create_task(interrupt_monitoring(gpio_line, ready_to_write))
    await ready_to_write.acquire()

    await perform_write(spi, 0xa0, bytearray([0xa8, 0x03, 0x00, 0x00, 0x00, 0xff]))
    print("waiting for gpio interrupt...")
    await ir_monitoring
    print("lock released, execution goes on")

    await perform_read(spi)
    await perform_read(spi)

    # await perform_tx(spi, gpio_line, 0xa0, bytearray([0xe4, 0x09, 0x00, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xff]))

    spi.close()
    gpio_line.close()


if __name__ == "__main__":
    asyncio.run(main())
