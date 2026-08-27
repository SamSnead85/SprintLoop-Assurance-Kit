import pytest


def test_passes():
    assert 2 + 2 == 4


def test_failure_is_visible_to_the_producer():
    assert 2 * 2 == 5


@pytest.mark.skip(reason="collector interoperability fixture")
def test_skipped():
    pass
