"""Lightweight smoke test for policy and feature extraction (run after installing requirements)."""
from backend.security import evaluate_rules
from backend.anomaly import features_for, score_anomaly


def test_sensitive_file_is_blocked():
    decision, _ = evaluate_rules("read", ".env")
    assert decision == "BLOCK"


def test_public_read_is_allowed_by_rules():
    decision, _ = evaluate_rules("read", "README.md")
    assert decision == "ALLOW"


def test_feature_shape_and_model_output():
    assert len(features_for("read", "README.md", 1)) == 4
    result = score_anomaly("read", "README.md", 1)
    assert result["model"] == "IsolationForest"
    assert 0 <= result["risk_score"] <= 100


if __name__ == "__main__":
    test_sensitive_file_is_blocked()
    test_public_read_is_allowed_by_rules()
    test_feature_shape_and_model_output()
    print("Smoke tests passed")
