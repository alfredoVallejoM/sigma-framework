import os
from typing import Union
from sigma.adapters.streams import FileStream, MemoryStream
from sigma.strategies.base import SigmaStrategy
from sigma.strategies.paranoid import ParanoidStrategy
from sigma.strategies.simultaneous import SimultaneousStrategy
from sigma.strategies.lightweight import LightweightStrategy
from sigma.strategies.realtime import RealTimeStrategy


class SigmaFactory:
    """
    Abstract Factory pattern to instantiate the appropriate hashing strategy.
    Provides high-level, deterministic entry points for files, bytes, and strings.
    """

    @staticmethod
    def get_strategy(mode: str, rounds: int = None) -> SigmaStrategy:
        mode = mode.lower()

        if mode == "paranoid":
            return ParanoidStrategy(rounds=rounds or 20)

        elif mode == "simultaneous":
            # La topología ahora es paramétrica (N hilos). 
            # Reutilizamos 'rounds' como límite de hilos si se desea, 
            # o dejamos el default (None = usar todos los cores).
            return SimultaneousStrategy(rounds=rounds or 5)

        elif mode == "lightweight":
            return LightweightStrategy(rounds=rounds or 5)

        elif mode == "realtime":
            # Realtime ignora las rondas por diseño (flujo continuo)
            return RealTimeStrategy(rounds=0)

        else:
            raise ValueError(f"Unknown strategy: {mode}")

    @staticmethod
    def hash_file(path: str, mode: str = "paranoid", rounds: int = None) -> str:
        """
        Processes a physical file stream.
        Guarantees O(1) RAM footprint via mmap/memoryviews internally.
        """
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
        """
        Processes a raw byte array from memory.
        """
        strategy = SigmaFactory.get_strategy(mode, rounds)
        stream = MemoryStream(data)
        return strategy.compute(stream)

    @staticmethod
    def hash_string(text: str, mode: str = "paranoid", rounds: int = None) -> str:
        """
        [SECURITY ENFORCEMENT]
        Processes a standard string. Forces UTF-8 encoding to prevent 
        cross-platform OS encoding collisions (e.g., Windows cp1252 vs Linux utf-8).
        Ideal for Key Derivation Functions (Passwords).
        """
        # Transform text to a deterministic byte array
        byte_data = text.encode("utf-8")
        return SigmaFactory.hash_bytes(byte_data, mode, rounds)
