import os
import re
from typing import List, Tuple

def luhn_checksum_valid(card_number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


class DLPScanner:
    """Detects sensitive information leaks and monitors removable media."""

    PATTERNS = {
        "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "US_SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        "AWS_KEY": re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "GITHUB_PAT": re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "JWT_TOKEN": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    }

    @classmethod
    def scan_text(cls, text: str) -> List[dict]:
        violations = []
        for match in cls.PATTERNS["CREDIT_CARD"].finditer(text):
            raw = re.sub(r"[ -]", "", match.group(0))
            if luhn_checksum_valid(raw):
                redacted = raw[:4] + "*" * (len(raw) - 8) + raw[-4:]
                violations.append({"rule": "CREDIT_CARD", "severity": "CRITICAL", "preview": redacted})
        for match in cls.PATTERNS["US_SSN"].finditer(text):
            val = match.group(0)
            redacted = "***-**-" + val.replace("-", "").replace(" ", "")[-4:]
            violations.append({"rule": "US_SSN", "severity": "HIGH", "preview": redacted})
        for match in cls.PATTERNS["AWS_KEY"].finditer(text):
            val = match.group(1)
            violations.append({"rule": "AWS_KEY", "severity": "CRITICAL", "preview": val[:4] + "..." + val[-4:]})
        for match in cls.PATTERNS["GITHUB_PAT"].finditer(text):
            val = match.group(1)
            violations.append({"rule": "GITHUB_PAT", "severity": "CRITICAL", "preview": val[:8] + "..."})
        if cls.PATTERNS["PRIVATE_KEY"].search(text):
            violations.append({"rule": "PRIVATE_KEY", "severity": "CRITICAL", "preview": "-----BEGIN PRIVATE KEY----- [REDACTED]"})
        for match in cls.PATTERNS["JWT_TOKEN"].finditer(text):
            val = match.group(0)
            violations.append({"rule": "JWT_TOKEN", "severity": "MEDIUM", "preview": val[:12] + "..."})
        return violations

    @classmethod
    def scan_file(cls, path: str, max_bytes: int = 5 * 1024 * 1024) -> List[dict]:
        if not os.path.isfile(path):
            return []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(max_bytes)
            return cls.scan_text(content)
        except Exception:
            return []


class USBMonitor:
    """Watches Linux mount points for removable USB media attachments."""

    def __init__(self):
        self._known_mounts = self._get_mounts()

    def _get_mounts(self) -> set:
        mounts = set()
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        dev, target, fstype = parts[0], parts[1], parts[2]
                        if "/media" in target or "/mnt" in target or dev.startswith("/dev/sd") or fstype in ("vfat", "exfat", "ntfs"):
                            mounts.add((dev, target, fstype))
        except Exception:
            pass
        return mounts

    def check_new_mounts(self) -> List[Tuple[str, str, str]]:
        current = self._get_mounts()
        new_items = current - self._known_mounts
        self._known_mounts = current
        return list(new_items)
