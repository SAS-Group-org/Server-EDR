"""Secure persistence for Server-EDR first-run configuration.

Configuration is stored as JSON with restrictive permissions. Secrets are
kept in the same protected file so they are never written to command-line
arguments or ordinary logs. Writes are atomic and existing files are reloaded
on startup through ``load``.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


DEFAULT_CONFIG_FILE = "edr_config.json"
SENSITIVE_KEYS = frozenset({"psk", "private_key", "key", "secret", "token", "password"})


class ConfigurationError(RuntimeError):
    """Raised when persisted configuration is missing or unsafe."""


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        raise ConfigurationError(f"Unable to protect configuration file {path}: {exc}") from exc


def _validate_private(path: Path) -> None:
    if os.name == "nt" or not path.exists():
        return
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigurationError(
            f"Configuration file {path} is accessible by group/other users (mode {mode:04o})"
        )


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError:
        pass
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _chmod_private(path)
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def load(path: str = DEFAULT_CONFIG_FILE) -> Dict[str, Any]:
    """Load and validate persisted configuration without silently weakening security."""
    config_path = Path(path)
    if not config_path.exists():
        return {}
    _validate_private(config_path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"Unable to read configuration {config_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a JSON object")
    return data


def save(values: Mapping[str, Any], path: str = DEFAULT_CONFIG_FILE) -> Dict[str, Any]:
    """Persist configuration atomically and return the stored mapping.

    Values are not logged or redacted in the file: the file itself is private
    (0600), which allows credentials to be reloaded without exposing them in
    process arguments or console output.
    """
    data = dict(values)
    data.setdefault("version", 1)
    _atomic_write(Path(path), json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def merge_defaults(path: str, defaults: Mapping[str, Any], overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Reload saved values, apply explicit overrides, and persist the result."""
    config = dict(defaults)
    config.update(load(path))
    if overrides:
        config.update({key: value for key, value in overrides.items() if value is not None})
    return save(config, path)


def redact(values: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a safe diagnostic representation with sensitive values removed."""
    result = {}
    for key, value in values.items():
        result[key] = "[REDACTED]" if key.lower() in SENSITIVE_KEYS else value
    return result
