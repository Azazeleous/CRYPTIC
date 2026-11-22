import pytest

from src.consensus.pacemaker import (
    MAX_ROUND, PacemakerError, timeout_deadline, timeout_event, timeout_seconds,
)


def test_timeout_backoff_is_bounded_and_deterministic():
    assert [timeout_seconds(i) for i in range(7)] == [5, 10, 20, 40, 60, 60, 60]
    assert timeout_seconds(MAX_ROUND) == 60


@pytest.mark.parametrize("bad", [True, -1, 1.0, "1", None, MAX_ROUND + 1])
def test_round_input_rejects_invalid_values(bad):
    with pytest.raises(PacemakerError):
        timeout_seconds(bad)


def test_deadline_uses_monotonic_duration():
    assert timeout_deadline(2, 100.25) == 120.25


@pytest.mark.parametrize("bad", [True, -1, float("inf"), float("nan"), "100"])
def test_deadline_rejects_invalid_monotonic_start(bad):
    with pytest.raises(PacemakerError):
        timeout_deadline(0, bad)


def test_timeout_event_is_not_emitted_before_deadline():
    assert timeout_event(
        height=7, source_round=2, started_monotonic=100.0, now_monotonic=119.99
    ) is None


def test_timeout_event_only_emits_a_higher_round_signal():
    event = timeout_event(
        height=7, source_round=2, started_monotonic=100.0, now_monotonic=120.0
    )
    assert event.height == 7
    assert event.source_round == 2
    assert event.target_round == 3
    assert event.timeout_seconds == 20


def test_timeout_event_rejects_time_reversal_and_bool_height():
    with pytest.raises(PacemakerError):
        timeout_event(height=1, source_round=0, started_monotonic=10, now_monotonic=9)
    with pytest.raises(PacemakerError):
        timeout_event(height=True, source_round=0, started_monotonic=10, now_monotonic=20)


def test_timeout_event_never_overflows_round_space():
    with pytest.raises(PacemakerError):
        timeout_event(
            height=1, source_round=MAX_ROUND, started_monotonic=1, now_monotonic=100
        )
