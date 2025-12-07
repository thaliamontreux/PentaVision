from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Dict


WATCH_EXTENSIONS = {".py", ".html", ".css", ".js", ".md", ".csv"}
IGNORE_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".idea", ".vscode"}


def _iter_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in WATCH_EXTENSIONS:
                continue
            path = os.path.join(dirpath, name)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            yield path, mtime


def _snapshot(root: str) -> Dict[str, float]:
    return {path: mtime for path, mtime in _iter_files(root)}


def _has_changes(prev: Dict[str, float], root: str) -> tuple[bool, Dict[str, float]]:
    current = {}
    changed = False

    for path, mtime in _iter_files(root):
        current[path] = mtime
        if path not in prev or prev[path] != mtime:
            changed = True

    if not changed and set(prev.keys()) != set(current.keys()):
        changed = True

    return changed, current


def _run_server() -> subprocess.Popen:
    print("[watch] starting server: python run.py")
    return subprocess.Popen([sys.executable, "run.py"], close_fds=False)


def main() -> None:
    project_root = os.path.dirname(os.path.abspath(__file__))
    state = _snapshot(project_root)
    proc = _run_server()

    try:
        while True:
            time.sleep(1.0)

            # If the process exited on its own, restart it.
            if proc.poll() is not None:
                print(f"[watch] server exited with code {proc.returncode}, restarting...")
                time.sleep(1.0)
                state = _snapshot(project_root)
                proc = _run_server()
                continue

            changed, new_state = _has_changes(state, project_root)
            if changed:
                print("[watch] file changes detected, restarting server...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                state = _snapshot(project_root)
                proc = _run_server()
    except KeyboardInterrupt:
        print("[watch] stopping watcher...")
    finally:
        if proc.poll() is None:
            proc.terminate()


if __name__ == "__main__":
    main()
