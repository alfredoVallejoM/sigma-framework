# sigma/core/primitives.py
import struct
from typing import Tuple
from .types import Word64


class BitwiseOps:
    """
    Secure implementation of ARX (Add-Rotate-Xor) operations
    over 64-bit virtual registers.
    """

    # Mask to enforce 64-bit arithmetic (0xFFFFFFFFFFFFFFFF)
    MASK_64 = 0xFFFFFFFFFFFFFFFF

    # Word size for rotations
    WORD_BITS = 64

    @staticmethod
    def add(a: Word64, b: Word64) -> Word64:
        """Modular addition: (a + b) mod 2^64"""
        return Word64((a + b) & BitwiseOps.MASK_64)

    @staticmethod
    def sub(a: Word64, b: Word64) -> Word64:
        """Modular subtraction: (a - b) mod 2^64"""
        return Word64((a - b) & BitwiseOps.MASK_64)

    @staticmethod
    def xor(a: Word64, b: Word64) -> Word64:
        """Bitwise XOR: a ^ b"""
        return Word64(a ^ b)

    @staticmethod
    def rotl(x: Word64, k: int) -> Word64:
        """
        Bitwise Rotate Left.
        k is taken modulo 64 for security.
        """
        k &= 63  # k % 64
        return Word64(
            ((x << k) | (x >> (BitwiseOps.WORD_BITS - k))) & BitwiseOps.MASK_64
        )

    @staticmethod
    def rotr(x: Word64, k: int) -> Word64:
        """
        Bitwise Rotate Right.
        """
        k &= 63
        return Word64(
            ((x >> k) | (x << (BitwiseOps.WORD_BITS - k))) & BitwiseOps.MASK_64
        )


class Codec:
    """
    Endianness Encoder/Decoder.
    Guarantees the system behaves identically on Intel (Little) and Mainframes (Big).
    """

    # Struct format: '>' (Big Endian), '8Q' (8 unsigned long long of 64 bits)
    _FORMAT = ">8Q"

    @staticmethod
    def bytes_to_words(data: bytes) -> "Tuple[Word64, ...]":
        """Converts 64 raw bytes into 8 64-bit words (Big Endian)."""
        if len(data) != 64:
            raise ValueError(f"Input must be exactly 64 bytes, got {len(data)}")
        return struct.unpack(Codec._FORMAT, data)

    @staticmethod
    def words_to_bytes(words: "Tuple[Word64, ...]") -> bytes:
        """Converts 8 64-bit words back to bytes."""
        return struct.pack(Codec._FORMAT, *words)
