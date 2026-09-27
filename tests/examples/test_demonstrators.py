from examples.shopping.zero_exposure import main as zero_exposure_main
from examples.travel.low_risk_context import main as low_risk_main
from examples.travel.progressive_disclosure import main as progressive_main


def test_low_risk_context_demo_completes(capsys) -> None:
    low_risk_main()
    output = capsys.readouterr().out
    assert "without a human approval step" in output


def test_progressive_disclosure_demo_completes(capsys) -> None:
    progressive_main()
    output = capsys.readouterr().out
    assert "approval_required" in output
    assert "date of birth was not requested or returned" in output


def test_zero_exposure_demo_never_prints_mock_secret(capsys) -> None:
    zero_exposure_main()
    output = capsys.readouterr().out
    assert "vault.use returns an opaque execution handle" in output
    assert "demo-booking-secret-NEVER-IN-MCP" not in output
