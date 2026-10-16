
"""Scan files for hardcoded secrets using regex-based detection."""

import argparse
import logging
import re
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)

SECRET_PATTERNS = (
    ("AWS Access Key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])")),
    ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Bearer Token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Stripe Secret", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}")),
    ("Generic Secret", re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)[\s:=\"']+[A-Za-z0-9!@#$%^&*()_+=\-/\\]{8,}")),
)


@dataclass
class Finding:
    path: str
    line_number: int
    pattern: str
    match: str

    def display(self) -> str:
        return f"{self.path}:{self.line_number}: {self.pattern}: {self.match.strip()}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan files or directories for potential hardcoded secrets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set the logging level",
    )
    return parser


def iter_files(target: Path):
    if target.is_file():
        yield target
        return

    for path in sorted(target.rglob("*")):
        if path.is_file() and not should_skip(path):
            yield path


def should_skip(path: Path) -> bool:
    skip_names = {".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules"}
    return any(part in skip_names for part in path.parts)


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                for pattern_name, pattern in SECRET_PATTERNS:
                    for match in pattern.finditer(line):
                        try:
                            relative_path = str(path.relative_to(root))
                        except ValueError:
                            relative_path = path.name
                        findings.append(
                            Finding(
                                path=path.name if path == root else relative_path,
                                line_number=line_number,
                                pattern=pattern_name,
                                match=match.group(0),
                            )
                        )
    except OSError as exc:
        LOGGER.warning("Skipping %s due to an error: %s", path, exc)
    return findings


def scan_path(target: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = target if target.is_file() else target.resolve()

    for file_path in iter_files(target):
        findings.extend(scan_file(file_path.resolve(), root))
    return findings


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)s: %(message)s",
    )

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        LOGGER.error("Path does not exist: %s", target)
        return 2

    LOGGER.info("Scanning %s for hardcoded secrets", target)
    findings = scan_path(target)

    if not findings:
        print("No hardcoded secrets detected.")
        return 0

    print(f"Found {len(findings)} potential secret(s):")
    for finding in findings:
        print(finding.display())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
