"""Exact SHA-256 round and message-schedule inverse primitives.

A round is bijective when its round constant and message-schedule word are
known. The digest alone does not supply those words. Schedule reversal requires
the final 16 expanded words (W[48:64]) as its boundary condition.
"""
from __future__ import annotations

MASK32 = 0xFFFFFFFF


def _rotr(value: int, count: int) -> int:
    value &= MASK32
    return ((value >> count) | (value << (32 - count))) & MASK32


def _big_sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _big_sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _small_sigma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _small_sigma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x) & z)


def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def _validate_words(words: tuple[int, ...] | list[int], count: int, label: str) -> None:
    if not isinstance(words, (tuple, list)) or len(words) != count:
        raise ValueError(f"{label}_must_contain_{count}_words")
    if any(isinstance(word, bool) or not isinstance(word, int) or not 0 <= word <= MASK32
           for word in words):
        raise ValueError(f"{label}_words_must_be_uint32")


def sha256_round_forward(state: tuple[int, ...], *, schedule_word: int,
                         round_constant: int) -> tuple[int, ...]:
    """Apply one SHA-256 round to eight 32-bit working-state words."""
    _validate_words(state, 8, "state")
    _validate_words((schedule_word, round_constant), 2, "round_input")
    a, b, c, d, e, f, g, h = state
    t1 = (h + _big_sigma1(e) + _ch(e, f, g) + round_constant + schedule_word) & MASK32
    t2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK32
    return ((t1 + t2) & MASK32, a, b, c, (d + t1) & MASK32, e, f, g)


def sha256_round_inverse(state_out: tuple[int, ...], *, schedule_word: int,
                         round_constant: int) -> tuple[int, ...]:
    """Invert one SHA-256 round exactly when W[t] and K[t] are known."""
    _validate_words(state_out, 8, "state_out")
    _validate_words((schedule_word, round_constant), 2, "round_input")
    a_out, b_out, c_out, d_out, e_out, f_out, g_out, h_out = state_out
    a, b, c = b_out, c_out, d_out
    e, f, g = f_out, g_out, h_out
    t2 = (_big_sigma0(a) + _maj(a, b, c)) & MASK32
    t1 = (a_out - t2) & MASK32
    d = (e_out - t1) & MASK32
    h = (t1 - _big_sigma1(e) - _ch(e, f, g) - round_constant - schedule_word) & MASK32
    return (a, b, c, d, e, f, g, h)


def expand_message_schedule(first_16_words: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    """Expand a 512-bit block's 16 words into SHA-256 W[0:64]."""
    _validate_words(first_16_words, 16, "message_block")
    words = list(first_16_words)
    for t in range(16, 64):
        value = (_small_sigma1(words[t - 2]) + words[t - 7]
                 + _small_sigma0(words[t - 15]) + words[t - 16]) & MASK32
        words.append(value)
    return tuple(words)


def reverse_message_schedule(last_16_words: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    """Recover W[0:64] from the known terminal schedule boundary W[48:64]."""
    _validate_words(last_16_words, 16, "schedule_tail")
    words: list[int | None] = [None] * 48 + list(last_16_words)
    for t in range(63, 15, -1):
        # At each descending step W[t], W[t-2], W[t-7], and W[t-15] are known.
        wt, wt2, wt7, wt15 = words[t], words[t - 2], words[t - 7], words[t - 15]
        if None in (wt, wt2, wt7, wt15):
            raise ValueError("schedule_boundary_insufficient")
        words[t - 16] = (wt - _small_sigma1(wt2) - wt7 - _small_sigma0(wt15)) & MASK32
    return tuple(int(word) for word in words)
