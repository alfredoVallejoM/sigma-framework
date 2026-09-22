"""Independent stdlib-only reference for Sigma Tree V1 ST0.

This module intentionally imports no code from ``sigma``.
"""

from __future__ import annotations

import hashlib
import struct

VERSION = 1
CHUNK = 65_536
ALGORITHMS = (1, 2, 3, 4)
DOMAIN_MAGIC = b"SIGTRDS1"
PROFILE_MAGIC = b"SIGTPRF1"


def u16(x: int) -> bytes:
    return x.to_bytes(2, "big")


def u32(x: int) -> bytes:
    return x.to_bytes(4, "big")


def u64(x: int) -> bytes:
    return x.to_bytes(8, "big")


def tlv(fields):
    return b"".join(struct.pack(">HI", t, len(v)) + v for t, v in fields)


def record(magic: bytes, fields):
    body = tlv(fields)
    return magic + u16(VERSION) + u32(len(body)) + body


def domain(d: int) -> bytes:
    return DOMAIN_MAGIC + u16(d)


def h(algorithm: int, data: bytes) -> bytes:
    if algorithm == 1:
        return hashlib.sha512(data).digest()
    if algorithm == 2:
        return hashlib.sha3_512(data).digest()
    if algorithm == 3:
        return hashlib.blake2b(data, digest_size=64).digest()
    if algorithm == 4:
        return hashlib.shake_256(data).digest(64)
    raise ValueError("unsupported algorithm")


def profile_bytes() -> bytes:
    algs = u16(4) + b"".join(u16(a) for a in ALGORITHMS)
    return record(PROFILE_MAGIC, ((1, u16(1)), (2, u32(CHUNK)), (3, algs)))


def leaf(index: int, raw: bytes):
    frame = record(
        b"SIGTLEAF",
        ((1, profile_bytes()), (2, u64(index)), (3, u64(index * CHUNK)), (4, u32(len(raw))), (5, raw)),
    )
    digests = tuple(h(a, domain(1) + frame) for a in ALGORITHMS)
    return (index, 1, len(raw), 0, digests)


def parent(left, right):
    ls, lc, lb, lh, ld = left
    rs, rc, rb, rh, rd = right
    if ls + lc != rs:
        raise ValueError("non-adjacent")
    height = max(lh, rh) + 1
    count = lc + rc
    length = lb + rb
    out = []
    for a, x, y in zip(ALGORITHMS, ld, rd):
        frame = record(
            b"SIGTJOIN",
            ((1, profile_bytes()), (2, u16(a)), (3, u32(height)), (4, u64(ls)), (5, u64(count)), (6, u64(length)), (7, x), (8, y)),
        )
        out.append(h(a, domain(2) + frame))
    return (ls, count, length, height, tuple(out))


def empty():
    out = []
    for a in ALGORITHMS:
        frame = record(b"SIGTEMPT", ((1, profile_bytes()), (2, u16(a)), (3, u64(0))))
        out.append(h(a, domain(3) + frame))
    return tuple(out)


def reduce_leaves(leaves):
    if not leaves:
        return (0, 0, empty())

    def root_range(lo: int, hi: int):
        n = hi - lo
        if n == 1:
            return leaves[lo]
        split = 1 << ((n - 1).bit_length() - 1)
        return parent(root_range(lo, lo + split), root_range(lo + split, hi))

    node = root_range(0, len(leaves))
    return (sum(x[2] for x in leaves), len(leaves), node[4])


def build(data: bytes):
    leaves = [
        leaf(i, data[i * CHUNK : (i + 1) * CHUNK])
        for i in range((len(data) + CHUNK - 1) // CHUNK)
    ]
    return reduce_leaves(leaves)
