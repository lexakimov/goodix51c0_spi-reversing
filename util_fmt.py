from datetime import datetime


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


def crop(s, length):
    return (s[:length - 3] + '...') if len(s) > length else s


def to_hex_string(byte_array: bytearray | bytes | list[int]):
    return ' '.join('{:02X}'.format(num) for num in byte_array)


def to_utf_string(byte_array: bytearray | bytes | list[int]):
    return bytearray(byte_array).decode('utf-8', errors='ignore')


def format_validity(is_valid: bool) -> str:
    return '🟢' if is_valid else '🔴'


def print_frame(color: Colors, prefix: str, width: int, rows: list[str]):
    indent = ' '
    max_len = width - len(indent) * 2 - 2
    log(color, f'{prefix}╔'.ljust(width - 1, '═') + '╗')
    for i, row_1 in enumerate(rows):
        for row_2 in row_1.split('\n'):
            rows_2 = []
            while len(row_2) > 0:
                rows_2.append(row_2[0:max_len].strip(' '))
                row_2 = row_2[max_len:].strip(' ')
            for row_3 in rows_2:
                row_3 = row_3.strip(' ')
                log(color, f'{prefix}║{indent}{row_3}'.ljust(width - 1, ' ') + '║')
        if i < len(rows) - 1:
            log(color, f'{prefix}╠'.ljust(width - 1, '═') + '╣')
    log(color, f'{prefix}╚'.ljust(width - 1, '═') + "╝")
