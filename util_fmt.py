from datetime import datetime


trim_long_strings = True


class Colors:
    END = "\033[0m"

    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    WHITE = "\033[0;37m"

    HI_BLACK = "\033[0;90m"
    HI_RED = "\033[0;91m"
    HI_GREEN = "\033[0;92m"
    HI_YELLOW = "\033[0;93m"
    HI_BLUE = "\033[0;94m"
    HI_PURPLE = "\033[0;95m"
    HI_CYAN = "\033[0;96m"
    HI_WHITE = "\033[0;97m"

    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"


def log(color, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(color, '[', timestamp, '] ', message, Colors.END, sep='')


def to_hex_string(byte_array: bytearray | bytes | list[int]):
    data = ' '.join('{:02X}'.format(num) for num in byte_array)
    return (data[:72] + '...') if trim_long_strings and len(data) > 75 else data


def to_utf_string(byte_array: bytearray | bytes | list[int]):
    length = _extract_length(byte_array)
    data = bytearray(byte_array[3:-1]).decode('utf-8', errors='ignore')
    return f'[length: {length}] ' + ((data[:72] + '...') if trim_long_strings and len(data) > 75 else data)


def format_validity(is_valid: bool) -> str:
    return '🟢' if is_valid else '🔴'


def _extract_length(packet: list[int] | bytearray) -> int:
    length_bytes = packet[1:3]
    length_int = int.from_bytes(length_bytes, byteorder="little")
    return length_int
