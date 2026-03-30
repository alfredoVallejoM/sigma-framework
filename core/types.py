# sigma/core/types.py
from typing import NewType, Tuple, List

# Define Word64 as a distinct type to avoid mixing it with indices or counters.
# Represents an unsigned 64-bit integer (0 to 2^64 - 1).
Word64 = NewType("Word64", int)

# A State Block is 8 64-bit words (512 bits total).
StateBlock = Tuple[Word64, Word64, Word64, Word64, Word64, Word64, Word64, Word64]

# Hash Vector: The internal representation of a digest (512 bits).
HashVector = StateBlock
