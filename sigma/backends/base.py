"""Backend contract for complete byte inputs."""

from abc import ABC, abstractmethod
from os import PathLike
from typing import Union

from sigma.anchors import AnchorEvidence, CrossWideEvidence
from sigma.spec import SigmaContextV2


class ExecutionBackend(ABC):
    """Execution policy; implementations must return canonical anchor evidence."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def compute_anchor(
        self, data: bytes, context: SigmaContextV2
    ) -> Union[AnchorEvidence, CrossWideEvidence]:
        pass


class FileExecutionBackend(ABC):
    """Backend accepting mutable source paths and already-stable snapshots."""

    @abstractmethod
    def compute_anchor_file(
        self, path: Union[str, PathLike], context: SigmaContextV2
    ) -> Union[AnchorEvidence, CrossWideEvidence]:
        pass

    def compute_anchor_snapshot(
        self, path: Union[str, PathLike], context: SigmaContextV2
    ) -> Union[AnchorEvidence, CrossWideEvidence]:
        """Hash a facade-owned immutable snapshot without copying it again."""

        return self.compute_anchor_file(path, context)
