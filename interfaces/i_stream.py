# sigma/interfaces/i_stream.py
from abc import ABC, abstractmethod
from typing import Optional

class IDataStream(ABC):
    """
    Contrato para fuentes de datos agnósticas.
    Debe soportar lectura por bloques eficiente sin cargar todo en RAM.
    """
    
    @abstractmethod
    def read(self, size: int) -> bytes:
        """
        Lee 'size' bytes del stream.
        Retorna bytes vacíos b'' si es EOF.
        """
        pass

    @abstractmethod
    def get_size(self) -> Optional[int]:
        """
        Retorna el tamaño total si se conoce (ej. archivo), 
        o None si es infinito (ej. socket/pipe).
        """
        pass
    
    @abstractmethod
    def reset(self) -> None:
        """Reinicia el puntero al inicio (si es soportado)."""
        pass