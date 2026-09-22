from app.decision.engine import Decision, decide


def test_scores_below_monitor_are_allow():
    for score in [0, 1, 50, 79]:
        assert decide(score) == Decision.ALLOW


def test_scores_from_monitor_threshold_are_monitor():
    for score in [80, 81, 85, 89]:
        assert decide(score) == Decision.MONITOR


def test_scores_from_block_threshold_are_block():
    for score in [90, 91, 95, 99, 100]:
        assert decide(score) == Decision.BLOCK


def test_exact_thresholds():
    assert decide(79) == Decision.ALLOW
    assert decide(80) == Decision.MONITOR
    assert decide(89) == Decision.MONITOR
    assert decide(90) == Decision.BLOCK


def test_custom_thresholds():
    assert decide(
        score=69,
        monitor_threshold=70,
        block_threshold=90,
    ) == Decision.ALLOW

    assert decide(
        score=70,
        monitor_threshold=70,
        block_threshold=90,
    ) == Decision.MONITOR

    assert decide(
        score=90,
        monitor_threshold=70,
        block_threshold=90,
    ) == Decision.BLOCK
