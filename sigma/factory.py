import os
from typing import Union, BinaryIO
from sigma.adapters.streams import FileStream, MemoryStream
from sigma.strategies.base import SigmaStrategy
from sigma.strategies.paranoid import ParanoidStrategy
from sigma.strategies.simultaneous import SimultaneousStrategy
from sigma.strategies.lightweight import LightweightStrategy
from sigma.strategies.realtime import RealTimeStrategy


class SigmaFactory:
    """
    Abstract Factory pattern to instantiate the appropriate hashing strategy.
    """

    @staticmethod
    def get_strategy(mode: str, rounds: int = None) -> SigmaStrategy:
        mode = mode.lower()

        if mode == "paranoid":
            return ParanoidStrategy(rounds=rounds or 20)

        elif mode == "simultaneous":
            return SimultaneousStrategy(rounds=rounds or 5)

        elif mode == "lightweight":
            # Structural Merkle Tree Strategy
            return LightweightStrategy(rounds=rounds or 5)

        elif mode == "realtime":
            # Streaming Strategy (Twisted Ring Accumulator)
            return RealTimeStrategy(rounds=0)

        else:
            raise ValueError(f"Unknown strategy: {mode}")

    @staticmethod
    def hash_file(path: str, mode: str = "paranoid", rounds: int = None) -> str:
        """Helper method for physical file streams."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Path does not exist: {path}")

        strategy = SigmaFactory.get_strategy(mode, rounds)
        stream = FileStream(path)
        try:
            return strategy.compute(stream)
        finally:
            stream.close()

    @staticmethod
    def hash_bytes(data: bytes, mode: str = "paranoid", rounds: int = None) -> str:
        """Helper method for in-memory byte buffers."""
        strategy = SigmaFactory.get_strategy(mode, rounds)
        stream = MemoryStream(data)
        return strategy.compute(stream)
