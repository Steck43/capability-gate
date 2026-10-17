import os

import pytest

from harness.t_adv_04_open_by_fd import DEFAULT_ITERATIONS, run


@pytest.mark.skipif(os.name != "posix", reason="open-by-fd uses Linux /proc identity")
def test_t_adv_04_scaffold_catches_repeated_swaps() -> None:
    result = run(DEFAULT_ITERATIONS)
    assert result == {
        "case": "T-ADV-04",
        "iterations": DEFAULT_ITERATIONS,
        "caught": DEFAULT_ITERATIONS,
        "false_allows": 0,
    }
