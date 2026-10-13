"""Framework-independent boundaries for a future bespoke model implementation."""

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True)
class Prediction:
    model_version: str
    health: str
    failure_risk: float | None
    horizon_hours: int | None


class Predictor(Protocol):
    def predict(self, features: Sequence[float | None]) -> Prediction: ...


class LocalTrainer(Protocol):
    def train(self, base_model: bytes, local_dataset: str) -> bytes:
        """Keep observations local and return a versioned model artifact."""
        ...
