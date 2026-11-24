"""Algorithm-independent inverse reconstruction with explicit verification."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")
U = TypeVar("U")


@dataclass(frozen=True)
class InverseReceipt(Generic[T, U]):
    accepted: bool
    target: T
    reconstructed: U | None = None
    forward_result: T | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class UnboundInverseModule(Generic[T, U]):
    """Injected inverse/forward operators; no hash or codec assumptions."""

    def __init__(self, inverse: Callable[[T], U], forward: Callable[[U], T],
                 equality: Callable[[T, T], bool] | None = None) -> None:
        if not callable(inverse) or not callable(forward):
            raise TypeError("forward_and_inverse_operators_must_be_callable")
        if equality is not None and not callable(equality):
            raise TypeError("equality_operator_must_be_callable")
        self.inverse = inverse
        self.forward = forward
        self.equality = equality or (lambda left, right: left == right)

    def solve(self, target: T) -> InverseReceipt[T, U]:
        try:
            reconstructed = self.inverse(target)
            forward_result = self.forward(reconstructed)
            accepted = bool(self.equality(forward_result, target))
            return InverseReceipt(
                accepted, target, reconstructed, forward_result,
                "F(F^-1(Y)) == Y" if accepted else "forward_reconstruction_mismatch",
            )
        except Exception as exc:
            return InverseReceipt(False, target, reason=f"inverse_or_forward_error:{type(exc).__name__}")


def verify_left_inverse(value: T, forward: Callable[[T], U],
                         inverse: Callable[[U], T],
                         equality: Callable[[T, T], bool] | None = None) -> bool:
    """Verify F^-1(F(x)) == x for one supplied domain value."""
    if not callable(forward) or not callable(inverse):
        raise TypeError("forward_and_inverse_operators_must_be_callable")
    compare = equality or (lambda left, right: left == right)
    try:
        return bool(compare(inverse(forward(value)), value))
    except Exception:
        return False
