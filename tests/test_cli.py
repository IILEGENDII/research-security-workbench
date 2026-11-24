from research_workbench.cli import main
import pytest


def test_version(capsys):
    with pytest.raises(SystemExit) as done:
        main(["--version"])
    assert done.value.code == 0
    assert capsys.readouterr().out == "0.1.0\n"
