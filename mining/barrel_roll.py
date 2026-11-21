"""Reversible bit, byte, and four-lane transforms for CRYPTIC.

These transforms are for scheduling, framing, and diagnostics. They MUST NOT
replace or modify the consensus proof-of-work hash preimage.
"""
from __future__ import annotations

from typing import Sequence


def _check_width(width: int) -> None:
    if not isinstance(width, int) or width <= 0:
        raise ValueError("width must be a positive integer")


def rotl(value: int, shift: int, width: int = 32) -> int:
    _check_width(width)
    if not isinstance(value, int) or value < 0 or value >= (1 << width):
        raise ValueError("value must fit the selected unsigned width")
    shift %= width
    mask = (1 << width) - 1
    if shift == 0:
        return value
    return ((value << shift) | (value >> (width - shift))) & mask


def rotr(value: int, shift: int, width: int = 32) -> int:
    _check_width(width)
    return rotl(value, -shift, width)


def rotate_bytes(data: bytes, shift: int) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data:
        return data
    shift %= len(data)
    return data[shift:] + data[:shift]


def inverse_rotate_bytes(data: bytes, shift: int) -> bytes:
    return rotate_bytes(data, -shift)


def interleave_lanes(data: bytes, lane_count: int = 4) -> tuple[bytes, ...]:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(lane_count, int) or lane_count < 1:
        raise ValueError("lane_count must be a positive integer")
    return tuple(data[i::lane_count] for i in range(lane_count))


def deinterleave_lanes(lanes: Sequence[bytes]) -> bytes:
    if not lanes or any(not isinstance(lane, bytes) for lane in lanes):
        raise ValueError("lanes must be a non-empty sequence of bytes")
    lane_count = len(lanes)
    out = bytearray()
    max_len = max(map(len, lanes), default=0)
    for column in range(max_len):
        for lane in range(lane_count):
            if column < len(lanes[lane]):
                out.append(lanes[lane][column])
    return bytes(out)


def roll_frame(
    data: bytes,
    *,
    bit_shift: int = 0,
    byte_shift: int = 0,
    lane_shift: int = 0,
    lane_count: int = 4,
) -> tuple[bytes, ...]:
    """Apply byte-wise bit rotation, byte rotation, then lane permutation."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    bit_shift %= 8
    bit_rolled = bytes(rotl(byte, bit_shift, 8) for byte in data)
    byte_rolled = rotate_bytes(bit_rolled, byte_shift)
    lanes = list(interleave_lanes(byte_rolled, lane_count))
    if lanes:
        lane_shift %= len(lanes)
        lanes = lanes[lane_shift:] + lanes[:lane_shift]
    return tuple(lanes)


def unroll_frame(
    lanes: Sequence[bytes],
    *,
    bit_shift: int = 0,
    byte_shift: int = 0,
    lane_shift: int = 0,
) -> bytes:
    """Invert roll_frame, reversing operation order."""
    if not lanes:
        return b""
    lane_shift %= len(lanes)
    ordered = tuple(lanes[-lane_shift:] + lanes[:-lane_shift]) if lane_shift else tuple(lanes)
    byte_rolled = deinterleave_lanes(ordered)
    bit_rolled = inverse_rotate_bytes(byte_rolled, byte_shift)
    bit_shift %= 8
    return bytes(rotr(byte, bit_shift, 8) for byte in bit_rolled)
