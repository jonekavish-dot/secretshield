"""Both engines run, so the same secret can be reported twice.

The dashboard is what judges read, so one secret must appear as one finding,
with the informative mask rather than Gitleaks' bare asterisks.
"""
from secretshield_scan import dedupe


def builtin(file="src/config.py", line=1, rule="aws-access-key", value="AKIA************QZXK"):
    return {
        "file": file, "line": line, "rule": rule,
        "severity": "Critical", "redacted_value": value,
        "remediation": "...", "engine": "builtin",
    }


def gitleaks(file="src/config.py", line=1, rule="aws-access-token", value="********"):
    return {
        "file": file, "line": line, "rule": rule,
        "severity": "Critical", "redacted_value": value,
        "remediation": "...", "engine": "gitleaks",
    }


def test_one_secret_reported_once():
    result = dedupe([builtin(), gitleaks()])
    assert len(result) == 1
    assert result[0]["engine"] == "builtin"
    assert result[0]["redacted_value"] == "AKIA************QZXK"


def test_gitleaks_still_reports_lines_the_builtin_engine_missed():
    """Gitleaks is the safety net: it must not be silenced where it is alone."""
    result = dedupe([builtin(line=1), gitleaks(line=9, rule="slack-token")])
    assert len(result) == 2
    assert {f["engine"] for f in result} == {"builtin", "gitleaks"}


def test_gitleaks_alone_is_kept():
    result = dedupe([gitleaks()])
    assert len(result) == 1
    assert result[0]["engine"] == "gitleaks"


def test_different_files_are_not_merged():
    result = dedupe([builtin(file="a.py"), gitleaks(file="b.py")])
    assert len(result) == 2


def test_identical_findings_collapse():
    assert len(dedupe([builtin(), builtin()])) == 1


def test_two_builtin_rules_on_one_line_are_both_kept():
    """A line can hold two real secrets; the built-in engine is never suppressed."""
    result = dedupe([builtin(rule="aws-access-key"), builtin(rule="hardcoded-password")])
    assert len(result) == 2


def test_results_are_sorted():
    result = dedupe([builtin(line=9), builtin(line=2), builtin(line=5)])
    assert [f["line"] for f in result] == [2, 5, 9]
