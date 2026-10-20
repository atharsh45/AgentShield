"""Fail-closed policy checks for the AgentShield demo gateway."""
import re
from pathlib import PurePosixPath, PureWindowsPath

SENSITIVE_MARKERS = (
    ".env", "secret", "credential", "password", "private_key", "id_rsa",
    "token", "api_key", "apikey", "access_key", "passwd",
)
ALLOWED_PUBLIC_FILES = {"readme.md", "license", "pyproject.toml", "requirements.txt"}
ALLOWED_ACTIONS = {"read", "list", "write", "update", "delete", "execute", "shell", "run_command"}


def normalize_resource(resource: str) -> str | None:
    """Return a normalized relative POSIX path, or None for unsafe paths."""
    if not isinstance(resource, str):
        return None
    value = resource.strip().replace("\\", "/").rstrip("/")
    if not value or "\x00" in value:
        return None
    # Reject absolute paths, drive-letter paths, UNC paths and traversal segments.
    if value.startswith("/") or PureWindowsPath(resource).is_absolute() or re.match(r"^[a-zA-Z]:", value):
        return None
    segments = value.split("/")
    if any(part in {".", ".."} for part in segments):
        return None
    if any(not part for part in segments):
        return None
    return "/".join(segments)


def evaluate_rules(action: str, resource: str) -> tuple[str, str]:
    """Return ALLOW/BLOCK/REVIEW. Unknown actions and paths fail closed."""
    if not isinstance(action, str) or not isinstance(resource, str):
        return "BLOCK", "Malformed action or resource was rejected."
    action = action.strip().lower()
    normalized = normalize_resource(resource)
    if not action or action not in ALLOWED_ACTIONS:
        return "BLOCK", "Unknown or malformed action was rejected."
    if normalized is None:
        return "BLOCK", "Absolute paths, traversal, and malformed resource paths are prohibited."

    lowered = normalized.lower()
    name = PurePosixPath(lowered).name
    if any(marker in lowered for marker in SENSITIVE_MARKERS):
        return "BLOCK", "Resource matches a sensitive-file or secret-related policy."

    if action in {"delete", "execute", "shell", "run_command", "write", "update"}:
        return "REVIEW", "Mutating or high-impact actions require explicit approval; this gateway will not execute them automatically."

    if action == "read" and name in ALLOWED_PUBLIC_FILES and "/" not in normalized:
        return "ALLOW", "Public project file is on the demo allowlist."

    if action == "list" and normalized in {"docs", "public"}:
        return "ALLOW", "Listing an approved public demo directory is permitted."

    if action in {"read", "list"} and (normalized.startswith("docs/") or normalized.startswith("public/")):
        return "ALLOW", "Read access is within a public demo directory."

    return "REVIEW", "No explicit allow policy matched; review is required by default."
