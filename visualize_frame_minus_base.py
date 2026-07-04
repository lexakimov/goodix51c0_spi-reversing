#!/usr/bin/env python3
# coding: utf-8

import argparse
from pathlib import Path

import crcmod.predefined
import matplotlib.colors as mcolors
import matplotlib.pyplot as plt
import numpy as np

# Для твоего goodix.dat = 13520 (ChicagoHS/HU)
OTP_SIZE = 0x40
FDT_SIZE = 0x0C
NAV_SIZE = 0x0C80
IMG_BASE_SIZE = 0x2800  # 64*80*2
FILE_CRC_SIZE = 4

IMG_ROWS = 64
IMG_COLS = 80

IMG_PACKET_SIZE = 0x1E04   # payload + crc
IMG_PACKED_SIZE = 0x1E00   # packed pixels


def crc32_mpeg(data: bytes) -> int:
    f = crcmod.predefined.mkCrcFun("crc-32-mpeg")
    return f(data) & 0xFFFFFFFF


def check_goodix_dat_crc(blob: bytes) -> None:
    # CRC в goodix.dat лежит little-endian
    exp_crc = int.from_bytes(blob[-4:], "little")
    act_crc = crc32_mpeg(blob[:-4])
    if act_crc != exp_crc:
        raise ValueError(f"goodix.dat CRC mismatch: exp={exp_crc:#010x}, act={act_crc:#010x}")


def check_frame_crc(payload: bytes) -> None:
    # Для кадров как ты просил: exp big-endian, act со свапом слов
    exp_crc = int.from_bytes(payload[-4:], "big")
    act_crc = crc32_mpeg(payload[:-4])
    act_crc = ((act_crc & 0xFFFF) << 16) | (act_crc >> 16)
    act_crc &= 0xFFFFFFFF
    if act_crc != exp_crc:
        raise ValueError(f"frame CRC mismatch: exp={exp_crc:#010x}, act={act_crc:#010x}")


def regroup_chicago_hu(src: bytes, size: int) -> np.ndarray:
    # Эквивалент ChicagoHUDataRegroup (ветка size != 0x960 для image/raw)
    if size % 6 != 0:
        raise ValueError("size must be multiple of 6")
    if len(src) < size:
        raise ValueError("src shorter than size")

    out = np.zeros((size // 6) * 4, dtype=np.uint16)
    out_pos = 0

    for i in range(0, size, 6):
        b0, b1, b2, b3, b4, b5 = src[i : i + 6]

        p0 = ((b0 & 0x0F) << 8) | b1
        p1 = (b3 << 4) | (b0 >> 4)
        p2 = ((b5 & 0x0F) << 8) | b2
        p3 = (b4 << 4) | (b5 >> 4)

        n0, n1, n2, n3 = out_pos, out_pos + 1, out_pos + 2, out_pos + 3
        out[(n0 % 0x40) * 0x50 + (n0 // 0x40)] = p0
        out[(n1 % 0x40) * 0x50 + (n1 // 0x40)] = p1
        out[(n2 % 0x40) * 0x50 + (n2 // 0x40)] = p2
        out[(n3 % 0x40) * 0x50 + (n3 // 0x40)] = p3

        out_pos += 4

    return out


def load_image_base_from_goodix_dat(path: Path) -> np.ndarray:
    blob = path.read_bytes()
    expected_size = OTP_SIZE + FDT_SIZE + NAV_SIZE + IMG_BASE_SIZE + FILE_CRC_SIZE
    if len(blob) != expected_size:
        raise ValueError(f"bad goodix.dat size: {len(blob)} (expected {expected_size})")

    check_goodix_dat_crc(blob)

    off = OTP_SIZE + FDT_SIZE + NAV_SIZE
    img_raw = blob[off : off + IMG_BASE_SIZE]
    return np.frombuffer(img_raw, dtype="<u2").reshape(IMG_ROWS, IMG_COLS)


def load_frame(path: Path, frame_format: str) -> np.ndarray:
    blob = path.read_bytes()

    if frame_format == "u16le":
        if len(blob) != IMG_BASE_SIZE:
            raise ValueError(f"u16le frame must be {IMG_BASE_SIZE} bytes, got {len(blob)}")
        return np.frombuffer(blob, dtype="<u2").reshape(IMG_ROWS, IMG_COLS)

    if frame_format == "packed":
        if len(blob) == IMG_PACKET_SIZE:
            check_frame_crc(blob)
            packed = blob[:-4]
        elif len(blob) == IMG_PACKED_SIZE:
            packed = blob
        else:
            raise ValueError(
                f"packed frame must be {IMG_PACKED_SIZE} or {IMG_PACKET_SIZE} bytes, got {len(blob)}"
            )
        px = regroup_chicago_hu(packed, IMG_PACKED_SIZE)
        return px.reshape(IMG_ROWS, IMG_COLS)

    raise ValueError("unknown frame format")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True, type=Path, help="path to goodix.dat")
    p.add_argument("--frame", required=True, type=Path, help="path to current frame")
    p.add_argument("--frame-format", choices=["packed", "u16le"], default="packed")
    p.add_argument("--save", type=Path, default=None, help="save figure to file")
    args = p.parse_args()

    base = load_image_base_from_goodix_dat(args.base).astype(np.int32)
    frame = load_frame(args.frame, args.frame_format).astype(np.int32)

    base = np.rot90(base, -1)
    frame = np.rot90(frame, -1)

    diff = frame.astype(np.int32) - base.astype(np.int32)

    # 1) убрать глобальный сдвиг (DC offset)
    d = diff - np.median(diff)

    # Если хочешь ещё контрастнее именно структуру папиллярных линий, добавь:

    d = d - d.mean(axis=1, keepdims=True)   # убрать построчный фон

    # robust-диапазон после вычитания построчного фона
    v = max(1, float(np.percentile(np.abs(d), 99)))
    norm = mcolors.TwoSlopeNorm(vmin=-v, vcenter=0, vmax=v)

    fig, ax = plt.subplots(1, 3, figsize=(8, 3))

    ax[0].imshow(frame, cmap="gray", vmin=0, vmax=4095)
    ax[0].set_title("Current frame")
    ax[0].axis("off")

    ax[1].imshow(base, cmap="gray", vmin=0, vmax=4095)
    ax[1].set_title("Image base")
    ax[1].axis("off")

    im = ax[2].imshow(d, cmap="gray", norm=norm)
    ax[2].set_title(f"Frame-Base gray\nmin={d.min():.1f} max={d.max():.1f}")
    ax[2].axis("off")
    fig.colorbar(im, ax=ax[2], fraction=0.046, pad=0.04)

    fig.tight_layout()

    if args.save:
        fig.savefig(args.save, dpi=150)
        print(f"saved: {args.save}")

    plt.show()


if __name__ == "__main__":
    main()

# Запуск:
#
# pip install numpy matplotlib crcmod
# python visualize_frame_minus_base.py --base ./logs_1/_cache/goodix.dat --frame frame.bin --frame-format packed
#
# Если твой frame.bin уже распакован (uint16 little-endian, 10240 байт), ставь --frame-format u16le.
