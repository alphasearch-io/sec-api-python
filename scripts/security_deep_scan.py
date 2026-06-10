"""High-signal repository security scan for incident-style artifacts."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


FORBIDDEN_BASENAMES = {
    "branch_structure.json",
    "config.bat",
    "temp_auto_push.bat",
    "temp_interactive_push.bat",
}

KNOWN_PAYLOAD_MARKERS = {
    "node ./public/fonts/" + "fa-solid-400.woff2",
    "rmcej" + "%otb%",
}

PACKAGE_LIFECYCLE_HOOKS = {
    "install",
    "postinstall",
    "preinstall",
    "prepare",
}

FONT_EXTENSIONS = {
    ".eot",
    ".otf",
    ".ttf",
    ".woff",
    ".woff2",
}

EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "coverage",
    "htmlcov",
    "node_modules",
}


@dataclass(frozen=True)
class SecurityFinding:
    path: str
    line: int
    kind: str
    detail: str


def _tracked_paths(root: Path) -> list[str] | None:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


def _fallback_paths(root: Path) -> list[str]:
    return [
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not any(part in EXCLUDED_PARTS for part in path.relative_to(root).parts)
    ]


def _candidate_paths(root: Path) -> list[str]:
    paths = _tracked_paths(root)
    if paths is None:
        paths = _fallback_paths(root)
    return [
        path
        for path in paths
        if not any(part in EXCLUDED_PARTS for part in Path(path).parts)
    ]


def _line_number(contents: str, marker: str) -> int:
    index = contents.find(marker)
    if index < 0:
        return 1
    return contents.count("\n", 0, index) + 1


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    except FileNotFoundError:
        return None


def _scan_forbidden_filename(relative_path: str) -> list[SecurityFinding]:
    basename = Path(relative_path).name
    if basename not in FORBIDDEN_BASENAMES:
        return []
    return [
        SecurityFinding(
            path=relative_path,
            line=1,
            kind="forbidden incident artifact filename",
            detail=f"{basename} is blocked from this repository",
        )
    ]


def _scan_known_markers(relative_path: str, contents: str) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for marker in KNOWN_PAYLOAD_MARKERS:
        if marker in contents:
            findings.append(
                SecurityFinding(
                    path=relative_path,
                    line=_line_number(contents, marker),
                    kind="known incident payload marker",
                    detail=marker,
                )
            )
    return findings


def _scan_vscode_tasks(relative_path: str, contents: str) -> list[SecurityFinding]:
    if relative_path != ".vscode/tasks.json":
        return []
    try:
        tasks_file = json.loads(contents)
    except json.JSONDecodeError:
        return [
            SecurityFinding(
                path=relative_path,
                line=1,
                kind="unparseable VS Code tasks file",
                detail="committed VS Code tasks must be valid JSON",
            )
        ]

    findings: list[SecurityFinding] = []
    tasks = tasks_file.get("tasks", [])
    if not isinstance(tasks, list):
        return findings

    for task in tasks:
        if not isinstance(task, dict):
            continue
        run_options = task.get("runOptions", {})
        if isinstance(run_options, dict) and run_options.get("runOn") == "folderOpen":
            findings.append(
                SecurityFinding(
                    path=relative_path,
                    line=_line_number(contents, "folderOpen"),
                    kind="VS Code folder-open task",
                    detail="folder-open tasks can execute code when the repository is opened",
                )
            )

        command = task.get("command")
        if isinstance(command, str) and "public/fonts" in command and "node" in command:
            findings.append(
                SecurityFinding(
                    path=relative_path,
                    line=_line_number(contents, command),
                    kind="suspicious VS Code task command",
                    detail=command,
                )
            )
    return findings


def _scan_vscode_settings(relative_path: str, contents: str) -> list[SecurityFinding]:
    if relative_path != ".vscode/settings.json":
        return []
    try:
        settings = json.loads(contents)
    except json.JSONDecodeError:
        return [
            SecurityFinding(
                path=relative_path,
                line=1,
                kind="unparseable VS Code settings file",
                detail="committed VS Code settings must be valid JSON",
            )
        ]

    if settings.get("task.allowAutomaticTasks") is not True:
        return []
    return [
        SecurityFinding(
            path=relative_path,
            line=_line_number(contents, "task.allowAutomaticTasks"),
            kind="VS Code automatic tasks enabled",
            detail="automatic tasks let folder-open tasks run without a prompt",
        )
    ]


def _scan_fake_font_payload(relative_path: str, contents: str) -> list[SecurityFinding]:
    path = Path(relative_path)
    if path.suffix not in FONT_EXTENSIONS:
        return []
    if "public/fonts" not in path.as_posix():
        return []

    javascript_markers = (
        "child_process",
        "eval(",
        "Function(",
        "process.env",
        "require(",
    )
    for marker in javascript_markers:
        if marker in contents:
            return [
                SecurityFinding(
                    path=relative_path,
                    line=_line_number(contents, marker),
                    kind="text JavaScript payload in font asset",
                    detail=f"font-like asset contains {marker}",
                )
            ]
    return []


def _scan_package_lifecycle_hooks(relative_path: str, contents: str) -> list[SecurityFinding]:
    if Path(relative_path).name != "package.json":
        return []
    try:
        package = json.loads(contents)
    except json.JSONDecodeError:
        return []

    scripts = package.get("scripts", {})
    if not isinstance(scripts, dict):
        return []

    findings: list[SecurityFinding] = []
    for hook in sorted(PACKAGE_LIFECYCLE_HOOKS):
        if hook not in scripts:
            continue
        findings.append(
            SecurityFinding(
                path=relative_path,
                line=_line_number(contents, f'"{hook}"'),
                kind="package lifecycle hook",
                detail=f"scripts.{hook} executes during dependency installation or packaging",
            )
        )
    return findings


def scan_security(root: Path | str = ".") -> list[SecurityFinding]:
    repo_root = Path(root)
    findings: list[SecurityFinding] = []

    for relative_path in _candidate_paths(repo_root):
        findings.extend(_scan_forbidden_filename(relative_path))

        file_path = repo_root / relative_path
        if not file_path.is_file():
            continue

        contents = _read_text(file_path)
        if contents is None:
            continue

        findings.extend(_scan_known_markers(relative_path, contents))
        findings.extend(_scan_vscode_tasks(relative_path, contents))
        findings.extend(_scan_vscode_settings(relative_path, contents))
        findings.extend(_scan_fake_font_payload(relative_path, contents))
        findings.extend(_scan_package_lifecycle_hooks(relative_path, contents))

    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", type=Path, help="Repository root to scan")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = scan_security(args.root)
    if findings:
        print("Security deep scan failed. Remove these tracked artifacts before merging:")
        for finding in findings:
            print(f"- {finding.path}:{finding.line}: {finding.kind} - {finding.detail}")
        return 1

    print("Security deep scan passed. No blocked incident artifacts or suspicious auto-run hooks found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
