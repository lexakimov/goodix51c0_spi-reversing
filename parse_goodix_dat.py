#!/usr/bin/env python3
import argparse
from dataclasses import dataclass
from pathlib import Path

import crcmod.predefined
import matplotlib.pyplot as plt
import numpy as np


@dataclass(frozen=True)
class Profile:
    name: str
    otp_size: int
    fdt_size: int
    nav_size: int
    base_img_size: int
    nav_rows: int
    nav_cols: int
    img_rows: int
    img_cols: int


PROFILES = [
    # ChicagoHS / ChicagoHU (DAT_1804ecc6c = 0xC)
    Profile("chicago_hs", otp_size=0x40, fdt_size=0x0C, nav_size=0x0C80, base_img_size=0x2800, nav_rows=25, nav_cols=64, img_rows=64, img_cols=80),

    # ChicagoT (DAT_1804ecc6c = 0xE)
    Profile("chicago_t", otp_size=0x40, fdt_size=0x14, nav_size=0x0C80, base_img_size=0x2D00, nav_rows=160, nav_cols=10, img_rows=160, img_cols=36),
]


def crc_check_file_blob(blob: bytes) -> None:
    if len(blob) < 4:
        raise ValueError("Слишком короткий файл")
    exp_crc = int.from_bytes(blob[-4:], "little")  # в goodix.dat CRC лежит little-endian
    crc32 = crcmod.predefined.mkCrcFun("crc-32-mpeg")
    act_crc = crc32(blob[:-4]) & 0xFFFFFFFF
    if act_crc != exp_crc:
        raise ValueError(f"CRC mismatch: exp={exp_crc:#010x}, act={act_crc:#010x}")


def expected_size(p: Profile) -> int:
    return p.otp_size + p.fdt_size + p.nav_size + p.base_img_size + 4


def detect_profile(file_size: int) -> Profile:
    matches = [p for p in PROFILES if expected_size(p) == file_size]
    if not matches:
        sizes = ", ".join(f"{p.name}:{expected_size(p)}" for p in PROFILES)
        raise ValueError(f"Не удалось определить профиль по размеру {file_size}. Ожидались: {sizes}")
    if len(matches) > 1:
        raise ValueError(f"Неоднозначный профиль для размера {file_size}: {[m.name for m in matches]}")
    return matches[0]


def parse_goodix_dat(path: Path, profile: Profile):
    data = path.read_bytes()
    if len(data) != expected_size(profile):
        raise ValueError(f"Размер {len(data)} != ожидаемому {expected_size(profile)} для {profile.name}")
    crc_check_file_blob(data)

    off = 0

    # 64
    otp = data[off:off + profile.otp_size]; off += profile.otp_size
    # 12
    fdt = data[off:off + profile.fdt_size]; off += profile.fdt_size
    # 3200
    nav_raw = data[off:off + profile.nav_size]; off += profile.nav_size
    # 10240
    img_raw = data[off:off + profile.base_img_size]; off += profile.base_img_size
    # 4
    crc_raw = data[off:off + 4]

    nav = np.frombuffer(nav_raw, dtype="<u2").reshape(profile.nav_rows, profile.nav_cols)
    img = np.frombuffer(img_raw, dtype="<u2").reshape(profile.img_rows, profile.img_cols)
    # img = np.rot90(img, k=-1)

    return otp, fdt, nav, img, crc_raw


def to_u8(img16: np.ndarray) -> np.ndarray:
    x = np.clip(img16.astype(np.float32), 0, 4095)
    lo, hi = float(x.min()), float(x.max())
    if hi <= lo:
        return np.zeros_like(x, dtype=np.uint8)
    return ((x - lo) * 255.0 / (hi - lo)).astype(np.uint8)


def show(img16: np.ndarray, title: str):
    plt.figure(figsize=(5, 8))
    plt.imshow(to_u8(img16), cmap="gray", interpolation="nearest")
    plt.title(title)
    plt.axis("off")
    plt.tight_layout()
    plt.show()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    ap.add_argument("--profile", choices=[p.name for p in PROFILES], default=None)
    args = ap.parse_args()

    blob = args.file.read_bytes()
    prof = next((p for p in PROFILES if p.name == args.profile), None) if args.profile else detect_profile(len(blob))

    otp, fdt, nav, img, _ = parse_goodix_dat(args.file, prof)

    print(f"profile: {prof.name}")
    print(f"size: {len(blob)} bytes")
    print(f"otp={len(otp)}, fdt={len(fdt)}, nav={nav.size} px ({nav.shape}), img={img.size} px ({img.shape})")

    show(nav, f"nav base ({prof.name})")
    show(img, f"image base ({prof.name})")

    # Если ориентация кажется неверной:
    # show(nav.T, "nav base (transpose)")
    # show(np.flipud(nav), "nav base (flipud)")
    # show(np.fliplr(nav), "nav base (fliplr)")


if __name__ == "__main__":
    main()

# python parse_goodix_nav.py ./logs_1/_cache/goodix.dat  --profile chicago_hs