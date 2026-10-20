"""Small Isolation Forest demo for tool-call anomaly detection.

This model is trained on synthetic normal-looking feature rows for demonstration.
Replace this bootstrap data with representative, approved telemetry before real use.
"""
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["action_risk", "resource_sensitivity", "request_burst", "unknown_resource"]


def build_model() -> IsolationForest:
    rng = np.random.default_rng(42)
    normal = np.column_stack([
        rng.choice([0.0, 0.2, 0.4], size=500, p=[0.55, 0.35, 0.10]),
        rng.choice([0.0, 0.1, 0.3], size=500, p=[0.70, 0.20, 0.10]),
        rng.poisson(1.5, size=500).clip(0, 6),
        rng.choice([0.0, 1.0], size=500, p=[0.85, 0.15]),
    ])
    model = IsolationForest(n_estimators=120, contamination=0.06, random_state=42)
    model.fit(normal)
    return model


MODEL = build_model()


def features_for(action: str, resource: str, recent_requests: int) -> list[float]:
    action = (action or "").lower().strip()
    resource = (resource or "").replace("\\", "/").lower().strip()
    action_risk = {"read": 0.0, "list": 0.0, "write": 0.4, "update": 0.4,
                   "delete": 0.9, "execute": 1.0, "shell": 1.0, "run_command": 1.0}.get(action, 0.6)
    sensitive = any(x in resource for x in (".env", "secret", "credential", "password", "private_key", "id_rsa", "token"))
    resource_sensitivity = 1.0 if sensitive else (0.35 if resource.startswith(("../", "/", "system/")) else 0.0)
    known = resource.startswith(("docs/", "public/")) or resource.rsplit("/", 1)[-1] in {
        "readme.md", "license", "pyproject.toml", "requirements.txt"
    }
    return [action_risk, resource_sensitivity, float(max(0, recent_requests)), 0.0 if known else 1.0]


def score_anomaly(action: str, resource: str, recent_requests: int) -> dict:
    row = np.asarray([features_for(action, resource, recent_requests)], dtype=float)
    prediction = int(MODEL.predict(row)[0])  # -1 means anomaly, +1 means inlier
    decision = float(MODEL.decision_function(row)[0])
    # A simple display score, not a calibrated probability.
    risk_score = round(max(0.0, min(100.0, 50.0 - decision * 100.0)), 1)
    return {
        "is_anomaly": prediction == -1,
        "risk_score": risk_score,
        "model": "IsolationForest",
        "score_note": "Heuristic display score, not a probability of attack.",
    }
