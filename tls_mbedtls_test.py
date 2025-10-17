from dataclasses import dataclass
from typing import Optional

import spidev
from mbedtls.tls import (
    HandshakeStep,
    ServerContext,
    TLSVersion,
    WantReadError,
    WantWriteError,
)
from mbedtls.tls import TLSConfiguration, TLSWrappedBuffer

AUX_CH = 0xA0  # управляющий канал
TLS_CH = 0xB0  # канал сырых TLS-записей


def make_header(channel: int, payload: bytes) -> bytes:
    length = len(payload).to_bytes(2, "little")
    checksum = (channel + length[0] + length[1]) & 0xFF
    return bytes((channel,)) + length + bytes((checksum,))


def to_hex_string(byte_array: bytearray | bytes | list[int]):
    return ' '.join('{:02X}'.format(num) for num in byte_array)


@dataclass
class GoodixLink:
    device: str
    speed_hz: int = 10_000_000

    def __post_init__(self):
        bus, dev = map(int, self.device.replace("spidev", "").split("."))
        self.spi = spidev.SpiDev()
        self.spi.open(bus, dev)
        self.spi.max_speed_hz = self.speed_hz
        self.spi.mode = 0

    def send(self, channel: int, payload: bytes) -> None:
        header = make_header(channel, payload)
        self.spi.xfer2(list(header))
        if payload:
            self.spi.xfer2(list(payload))
        print(f"sent: {to_hex_string(header)} --- {to_hex_string(payload)}")

    def recv(self) -> tuple[int, bytes]:
        header = bytes(self.spi.xfer2([0, 0, 0, 0]))
        channel, length_lo, length_hi, checksum = header
        if (channel + length_lo + length_hi) & 0xFF != checksum:
            raise RuntimeError(f"bad header checksum {header.hex()}")
        length = length_lo | (length_hi << 8)
        payload = bytes(self.spi.xfer2([0] * length)) if length else b""
        return channel, payload

    def send_control(self, payload: bytes) -> None:
        self.send(AUX_CH, payload)

    def send_tls(self, record: bytes) -> None:
        self.send(TLS_CH, record)

    def recv_tls(self, timeout_ms: int = 50) -> Optional[bytes]:
        # В реальном коде нужен опрос IRQ; здесь — простейший поллинг.
        channel, payload = self.recv()
        if channel != TLS_CH:
            handle_non_tls(channel, payload)  # дописать обработку остальных сообщений
            return None
        return payload


def handle_non_tls(channel: int, payload: bytes) -> None:
    # заглушка; сюда попадают ответы ACK, статусы MCU и т.д.
    pass


class GoodixTLSBridge:
    def __init__(self, spi_dev: str, psk: bytes):
        self.link = GoodixLink(spi_dev)
        config = TLSConfiguration(
            validate_certificates=False,
            ciphers=("TLS-PSK-WITH-AES-128-GCM-SHA256",),
            lowest_supported_version=TLSVersion.TLSv1_2,
            highest_supported_version=TLSVersion.TLSv1_2,
            pre_shared_key_store={"Client_identity": psk},
        )
        self.ctx = ServerContext(config)
        self.tls = TLSWrappedBuffer(self.ctx)

    def start_handshake(self):
        self.link.send_control(bytes.fromhex("D1 03 00 00 00 D7"))
        self._flush_outgoing()
        while self.tls._handshake_state is not HandshakeStep.HANDSHAKE_OVER:
            try:
                self.tls.do_handshake()
            except WantWriteError:
                self._flush_outgoing()
            except WantReadError:
                frame = self._wait_tls_record()
                if frame:
                    self.tls.receive_from_network(frame)
            else:
                self._flush_outgoing()
        self._flush_outgoing()

    def send_encrypted(self, plaintext: bytes):
        self.tls.write(plaintext)
        self._flush_outgoing()

    def recv_encrypted(self) -> bytes:
        while True:
            try:
                data = self.tls.read(16384)
                if data:
                    return data
            except WantReadError:
                pass
            frame = self._wait_tls_record()
            if frame:
                self.tls.receive_from_network(frame)

    def _flush_outgoing(self):
        while True:
            chunk = self.tls.peek_outgoing(4096)
            if not chunk:
                break
            self.link.send_tls(chunk)
            self.tls.consume_outgoing(len(chunk))

    def _wait_tls_record(self):
        while True:
            frame = self.link.recv_tls()
            if frame is not None:
                return frame


# пример использования
def main():
    psk = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    bridge = GoodixTLSBridge("spidev1.0", psk)
    bridge.start_handshake()
    bridge.send_encrypted(b"\x00\x01 request")
    reply = bridge.recv_encrypted()
    print("TLS reply:", reply.hex())


if __name__ == "__main__":
    main()
