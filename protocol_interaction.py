import asyncio

import periphery
from periphery import CdevGPIO
from spidev import SpiDev


class Log:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def green(message):
        print(Log.OKGREEN, message, Log.ENDC, sep='')

    @staticmethod
    def cyan(message):
        print(Log.OKCYAN, message, Log.ENDC, sep='')

    @staticmethod
    def red(message):
        print(Log.FAIL, message, Log.ENDC, sep='')

    @staticmethod
    def white(message):
        print(Log.HEADER, message, Log.ENDC, sep='')


def format_to_hex_string(byte_array: bytearray | bytes):
    return ' '.join('{:02X}'.format(num) for num in byte_array)


def format_to_utf_string(byte_array: bytearray | bytes):
    return bytearray(byte_array).decode('utf-8', errors='ignore')


def make_cmd_packet(cmd: int, payload: bytes | list) -> bytearray:
    """
    cmd
        command 0xA0
    payload
        bytes of payload
    """
    payload_length: bytes = len(payload).to_bytes(2, 'little')
    command_packet = bytearray([cmd]) + payload_length
    checksum: bytes = sum(command_packet).to_bytes()
    command_packet += checksum

    return command_packet


def reset_spi():
    Log.red("reset...")
    gpio_reset = CdevGPIO('/dev/gpiochip0', 140, 'out', label='fp-reset')
    for i in (1, 0):
        gpio_reset.write(bool(i))
    gpio_reset.close()


async def interrupt_monitoring(gpio_line: periphery.CdevGPIO, ready_to_write_lock: asyncio.Lock):
    Log.cyan("interrupt_monitoring started")
    ready_to_write_lock.release()
    i = 1
    while True:
        await asyncio.sleep(0.001)
        r = gpio_line.read()
        if r:
            Log.cyan(f"release read lock on iteration {i}")
            return True
        i += 1
        if i > 5000:
            Log.red(f"timeout {i}")
            return False


def validate_checksum(packet: list[int] | bytearray) -> bool:
    checksum = packet[-1]
    fact_sum = sum(packet[:-1])
    fact_sum_first_byte = fact_sum.to_bytes(10, byteorder="little")[0]
    return checksum == fact_sum_first_byte


def extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int


async def perform_tx(spi: SpiDev, interrupt_line: CdevGPIO, cmd: int, payload: bytes):
    ready_to_write_lock = asyncio.Lock()
    await ready_to_write_lock.acquire()
    print("latch created")

    ir_monitoring = asyncio.create_task(interrupt_monitoring(interrupt_line, ready_to_write_lock))
    await ready_to_write_lock.acquire()

    print("start writing bytes")

    cmd_packet = make_cmd_packet(cmd, payload)
    spi.writebytes(cmd_packet)
    Log.white(f"sent command: {format_to_hex_string(cmd_packet)}")
    spi.writebytes(payload)
    Log.white(f"sent payload : {format_to_hex_string(payload)} | {format_to_utf_string(payload)}")

    print("waiting for gpio interrupt...")
    await ir_monitoring
    print("lock released, execution goes on")

    response_1 = spi.readbytes(4)
    is_valid = validate_checksum(response_1)
    Log.white(f"received package: {format_to_hex_string(response_1)} | checksum valid {is_valid}")

    length = extract_length(response_1)
    response_2 = spi.readbytes(length)
    Log.white(f"received package: {format_to_hex_string(response_2)} | {format_to_utf_string(response_2)}")

    validate_checksum(response_2)


async def main():
    gpio_line = CdevGPIO('/dev/gpiochip0', 321, 'in', edge='both', bias='default')
    spi = SpiDev(1, 0)
    spi.max_speed_hz = 0x00989680  # 10 000 000
    # spi.mode = 0b00

    # reset_spi()

    await perform_tx(spi, gpio_line, 0xa0, bytearray([0xe4, 0x09, 0x00, 0x02, 0x00, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0xff]))
    # read    4 -  0000: a0 06 00 a6
    # read    6 -  0000: b0 03 00 e4 07 0c

    await perform_tx(spi, gpio_line, 0xa0, bytearray([0xa8, 0x03, 0x00, 0x00, 0x00, 0xff]))
    # read    4 -  0000: a0 1a 00 ba
    # read   26 -  0000: a8 17 00 47 46 5f 48 43 34 36 30 53 45 43 5f 41
    # read   26 -  0010: 50 50 5f 31 34 32 31 30 00 68

    spi.close()
    gpio_line.close()


if __name__ == "__main__":
    asyncio.run(main())
