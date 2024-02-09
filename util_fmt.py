from datetime import datetime

log_isr_events = False
log_synchronization_events = False
log_manual_sleeps = False

hex_string_length_limit = 80
utf_string_length_limit = 80


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
    return (data[:hex_string_length_limit - 3] + '...') if len(data) > hex_string_length_limit else data


def to_utf_string(byte_array: bytearray | bytes | list[int]):
    data = bytearray(byte_array[3:-1]).decode('utf-8', errors='ignore')
    return (data[:utf_string_length_limit - 3] + '...') if len(data) > utf_string_length_limit else data


def format_validity(is_valid: bool) -> str:
    return '🟢' if is_valid else '🔴'
