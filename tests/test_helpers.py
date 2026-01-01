"""Test helper functions in audit module."""

from mcp_security.audit import (
    _evaluate_condition,
    _format_message,
    _collect_issues_from_analyzer,
    _add_issues_to_recommendations,
    _add_issues_to_recommendations_prioritized,
)


def test_evaluate_condition_greater_than():
    """Test > operator."""
    analyzer = {"count": 10}
    condition = {"field": "count", "op": ">", "value": 5}
    assert _evaluate_condition(analyzer, condition) is True

    condition = {"field": "count", "op": ">", "value": 15}
    assert _evaluate_condition(analyzer, condition) is False


def test_evaluate_condition_less_than():
    """Test < operator."""
    analyzer = {"percentage": 50}
    condition = {"field": "percentage", "op": "<", "value": 60}
    assert _evaluate_condition(analyzer, condition) is True

    condition = {"field": "percentage", "op": "<", "value": 40}
    assert _evaluate_condition(analyzer, condition) is False


def test_evaluate_condition_equals():
    """Test == operator."""
    analyzer = {"status": "active", "port": 22}
    condition = {"field": "status", "op": "==", "value": "active"}
    assert _evaluate_condition(analyzer, condition) is True

    condition = {"field": "port", "op": "==", "value": 80}
    assert _evaluate_condition(analyzer, condition) is False


def test_evaluate_condition_not_equals():
    """Test != operator."""
    analyzer = {"policy": "deny"}
    condition = {"field": "policy", "op": "!=", "value": "allow"}
    assert _evaluate_condition(analyzer, condition) is True

    condition = {"field": "policy", "op": "!=", "value": "deny"}
    assert _evaluate_condition(analyzer, condition) is False


def test_evaluate_condition_nested_fields():
    """Test nested field access (e.g., systemd.critical_down)."""
    analyzer = {"systemd": {"critical_down": 2, "failed_count": 5}}
    condition = {"field": "systemd.critical_down", "op": ">", "value": 0}
    assert _evaluate_condition(analyzer, condition) is True

    condition = {"field": "systemd.failed_count", "op": "==", "value": 5}
    assert _evaluate_condition(analyzer, condition) is True


def test_evaluate_condition_none_analyzer():
    """Test with None analyzer."""
    condition = {"field": "count", "op": ">", "value": 5}
    assert _evaluate_condition(None, condition) is False


def test_format_message_simple():
    """Test message formatting with single placeholder."""
    analyzer = {"count": 42}
    template = "Found {count} issues"
    result = _format_message(template, analyzer)
    assert result == "Found 42 issues"


def test_format_message_multiple_placeholders():
    """Test message formatting with multiple placeholders."""
    analyzer = {"total": 100, "failed": 5, "percentage": 95}
    template = "{failed} out of {total} failed ({percentage}% success)"
    result = _format_message(template, analyzer)
    assert result == "5 out of 100 failed (95% success)"


def test_format_message_nested_fields():
    """Test formatting with nested field access."""
    analyzer = {"systemd": {"failed_count": 3}}
    template = "Systemd has {systemd.failed_count} failed units"
    result = _format_message(template, analyzer)
    assert result == "Systemd has 3 failed units"


def test_format_message_no_placeholders():
    """Test message with no placeholders."""
    analyzer = {"count": 10}
    template = "Static message"
    result = _format_message(template, analyzer)
    assert result == "Static message"


def test_format_message_none_analyzer():
    """Test formatting with None analyzer."""
    template = "Test {field}"
    result = _format_message(template, None)
    assert result == "Test {field}"  # Should return template unchanged


def test_collect_issues_from_analyzer():
    """Test collecting issues from analyzer result."""
    analyzer = {
        "issues": [
            {"severity": "high", "message": "Issue 1", "recommendation": "Fix 1"},
            {"severity": "medium", "message": "Issue 2", "recommendation": "Fix 2"},
        ]
    }
    issues = _collect_issues_from_analyzer(analyzer)
    assert len(issues) == 2
    assert issues[0]["severity"] == "high"
    assert issues[1]["severity"] == "medium"


def test_collect_issues_from_none_analyzer():
    """Test collecting issues from None analyzer."""
    issues = _collect_issues_from_analyzer(None)
    assert issues == []


def test_collect_issues_no_issues_key():
    """Test collecting issues when 'issues' key doesn't exist."""
    analyzer = {"checked": True, "count": 5}
    issues = _collect_issues_from_analyzer(analyzer)
    assert issues == []


def test_add_issues_to_recommendations():
    """Test adding issues to recommendations list."""
    recommendations = []
    issues = [
        {"severity": "critical", "message": "Critical issue", "recommendation": "Fix now"},
        {"severity": "high", "message": "High issue", "recommendation": "Fix soon"},
    ]
    _add_issues_to_recommendations(recommendations, issues)

    assert len(recommendations) == 2
    assert recommendations[0]["priority"] == "critical"
    assert recommendations[0]["title"] == "Critical issue"
    assert recommendations[0]["description"] == "Fix now"
    assert recommendations[0]["command"] is None


def test_add_issues_to_recommendations_prioritized_append():
    """Test adding issues to end of recommendations."""
    recommendations = [{"priority": "high", "title": "Existing"}]
    issues = [{"severity": "medium", "message": "New issue", "recommendation": "Fix"}]

    _add_issues_to_recommendations_prioritized(recommendations, issues, insert_at_front=False)

    assert len(recommendations) == 2
    assert recommendations[0]["priority"] == "high"  # Original first
    assert recommendations[1]["priority"] == "medium"  # New at end


def test_add_issues_to_recommendations_prioritized_prepend():
    """Test adding issues to front of recommendations."""
    recommendations = [{"priority": "medium", "title": "Existing"}]
    issues = [{"severity": "critical", "message": "Critical issue", "recommendation": "Fix now"}]

    _add_issues_to_recommendations_prioritized(recommendations, issues, insert_at_front=True)

    assert len(recommendations) == 2
    assert recommendations[0]["priority"] == "critical"  # New at front
    assert recommendations[1]["priority"] == "medium"  # Original second
