from __future__ import annotations

import json
import os
import queue
import threading
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from tkinter import BooleanVar, END, StringVar, Tk, Toplevel, ttk
from tkinter import filedialog, messagebox
from typing import TYPE_CHECKING

from diagnose_site import run_diagnostics, write_reports

if TYPE_CHECKING:
    from diagnose_site import DiagnosticsRunResult


@dataclass
class AppSettings:
    base_url: str = ""
    token: str = ""
    max_pages: int = 250
    timeout: float = 12.0
    delay_ms: int = 0
    script_path: str = ""
    urls_file: str = ""
    reveal_token: bool = False


def _app_data_dir() -> Path:
    appdata = os.getenv("APPDATA")
    if appdata:
        return Path(appdata) / "PentaVision" / "Diagnostics"
    return Path.home() / ".pentavision" / "diagnostics"


def _settings_path() -> Path:
    return _app_data_dir() / "settings.json"


def _load_settings() -> AppSettings:
    p = _settings_path()
    if not p.exists():
        return AppSettings(urls_file=str(Path.cwd() / "diagnostics_urls.json"))
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return AppSettings(urls_file=str(Path.cwd() / "diagnostics_urls.json"))

    s = AppSettings()
    s.base_url = str(data.get("base_url") or "")
    s.token = str(data.get("token") or "")
    s.max_pages = int(data.get("max_pages") or 250)
    s.timeout = float(data.get("timeout") or 12.0)
    s.delay_ms = int(data.get("delay_ms") or 0)
    s.script_path = str(data.get("script_path") or "")
    default_urls = str(
        Path.cwd() / "diagnostics_urls.json",
    )
    s.urls_file = str(
        data.get("urls_file")
        or default_urls
    )
    s.reveal_token = bool(data.get("reveal_token") or False)
    return s


def _save_settings(s: AppSettings) -> None:
    p = _settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "base_url": s.base_url,
        "token": s.token,
        "max_pages": int(s.max_pages),
        "timeout": float(s.timeout),
        "delay_ms": int(s.delay_ms),
        "script_path": s.script_path,
        "urls_file": s.urls_file,
        "reveal_token": bool(s.reveal_token),
    }
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_seed_urls(urls_file: str) -> list[str]:
    if not urls_file:
        return []
    p = Path(urls_file)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []

    paths = data.get("paths")
    if not isinstance(paths, list):
        return []
    out: list[str] = []
    for item in paths:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s:
            continue
        out.append(s)
    return out


def _paths_to_absolute(base_url: str, paths: list[str]) -> list[str]:
    base = (base_url or "").rstrip("/")
    out: list[str] = []
    for p in paths:
        p2 = p.strip()
        if not p2:
            continue
        if p2.startswith("http://") or p2.startswith("https://"):
            out.append(p2)
            continue
        if not p2.startswith("/"):
            p2 = "/" + p2
        out.append(base + p2)
    return out


class CompanionApp:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("PentaVision Diagnostics Companion")
        self.root.geometry("1120x720")

        self.msg_q: queue.Queue[str] = queue.Queue()
        self.worker: threading.Thread | None = None
        self.current_result: DiagnosticsRunResult | None = None
        self.current_html: str | None = None
        self.current_json: str | None = None

        s = _load_settings()

        self.base_url = StringVar(value=s.base_url)
        self.token = StringVar(value=s.token)
        self.max_pages = StringVar(value=str(s.max_pages))
        self.timeout = StringVar(value=str(s.timeout))
        self.delay_ms = StringVar(value=str(s.delay_ms))
        self.script_path = StringVar(value=s.script_path)
        self.urls_file = StringVar(value=s.urls_file)
        self.reveal_token = BooleanVar(value=s.reveal_token)

        self._build_ui()
        self._refresh_seed_urls()
        self._tick()

    def _build_ui(self) -> None:
        frm = ttk.Frame(self.root, padding=12)
        frm.pack(fill="both", expand=True)

        top = ttk.Frame(frm)
        top.pack(fill="x")

        ttk.Label(top, text="Base URL").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.base_url, width=60).grid(
            row=0, column=1, sticky="we", padx=(8, 12)
        )

        ttk.Label(top, text="Token").grid(
            row=1,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        self.token_entry = ttk.Entry(
            top,
            textvariable=self.token,
            width=60,
            show="*",
        )
        self.token_entry.grid(
            row=1,
            column=1,
            sticky="we",
            padx=(8, 12),
            pady=(8, 0),
        )

        ttk.Checkbutton(
            top,
            text="Show",
            variable=self.reveal_token,
            command=self._sync_token_visibility,
        ).grid(row=1, column=2, sticky="w", pady=(8, 0))

        ttk.Label(top, text="Max pages").grid(row=0, column=3, sticky="w")
        ttk.Entry(top, textvariable=self.max_pages, width=10).grid(
            row=0, column=4, sticky="w", padx=(8, 12)
        )

        ttk.Label(top, text="Timeout (s)").grid(
            row=1,
            column=3,
            sticky="w",
            pady=(8, 0),
        )
        ttk.Entry(top, textvariable=self.timeout, width=10).grid(
            row=1, column=4, sticky="w", padx=(8, 12), pady=(8, 0)
        )

        ttk.Label(top, text="Delay (ms)").grid(row=0, column=5, sticky="w")
        ttk.Entry(top, textvariable=self.delay_ms, width=10).grid(
            row=0, column=6, sticky="w", padx=(8, 0)
        )

        top.grid_columnconfigure(1, weight=1)

        mid = ttk.Frame(frm)
        mid.pack(fill="x", pady=(12, 0))

        ttk.Label(mid, text="Script (JSON)").grid(row=0, column=0, sticky="w")
        ttk.Entry(mid, textvariable=self.script_path).grid(
            row=0, column=1, sticky="we", padx=(8, 8)
        )
        ttk.Button(mid, text="Browse", command=self._pick_script).grid(
            row=0, column=2, sticky="w"
        )

        ttk.Label(mid, text="URL list file").grid(
            row=1,
            column=0,
            sticky="w",
            pady=(8, 0),
        )
        ttk.Entry(mid, textvariable=self.urls_file).grid(
            row=1, column=1, sticky="we", padx=(8, 8), pady=(8, 0)
        )
        ttk.Button(mid, text="Browse", command=self._pick_urls_file).grid(
            row=1, column=2, sticky="w", pady=(8, 0)
        )
        ttk.Button(
            mid,
            text="Reload URLs",
            command=self._refresh_seed_urls,
        ).grid(
            row=1,
            column=3,
            sticky="w",
            padx=(8, 0),
            pady=(8, 0),
        )

        mid.grid_columnconfigure(1, weight=1)

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(12, 0))

        self.run_btn = ttk.Button(
            actions,
            text="Run diagnostics",
            command=self._run,
        )
        self.run_btn.pack(side="left")

        ttk.Button(
            actions,
            text="Open HTML report",
            command=self._open_html,
        ).pack(
            side="left",
            padx=(8, 0),
        )
        ttk.Button(
            actions,
            text="Show summary windows",
            command=self._open_windows,
        ).pack(
            side="left",
            padx=(8, 0),
        )
        ttk.Button(actions, text="Save settings", command=self._save).pack(
            side="right"
        )

        bottom = ttk.PanedWindow(frm, orient="horizontal")
        bottom.pack(fill="both", expand=True, pady=(12, 0))

        left = ttk.Labelframe(bottom, text="Seed URL list")
        right = ttk.Labelframe(bottom, text="Run log")
        bottom.add(left, weight=1)
        bottom.add(right, weight=2)

        self.urls_list = tk_listbox(left)
        self.urls_list.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_list = tk_listbox(right)
        self.log_list.pack(fill="both", expand=True, padx=10, pady=10)

        self._sync_token_visibility()

    def _sync_token_visibility(self) -> None:
        self.token_entry.configure(show="" if self.reveal_token.get() else "*")

    def _pick_script(self) -> None:
        p = filedialog.askopenfilename(
            title="Select diagnostic script",
            filetypes=[("JSON", "*.json"), ("All files", "*")],
        )
        if p:
            self.script_path.set(p)

    def _pick_urls_file(self) -> None:
        p = filedialog.askopenfilename(
            title="Select URL list file",
            filetypes=[("JSON", "*.json"), ("All files", "*")],
        )
        if p:
            self.urls_file.set(p)
            self._refresh_seed_urls()

    def _refresh_seed_urls(self) -> None:
        self.urls_list.delete(0, END)
        paths = _load_seed_urls(self.urls_file.get())
        abs_urls = _paths_to_absolute(self.base_url.get(), paths)
        for u in abs_urls:
            self.urls_list.insert(END, u)

    def _save(self) -> None:
        s = AppSettings(
            base_url=self.base_url.get().strip(),
            token=self.token.get().strip(),
            max_pages=int(self.max_pages.get() or "250"),
            timeout=float(self.timeout.get() or "12"),
            delay_ms=int(self.delay_ms.get() or "0"),
            script_path=self.script_path.get().strip(),
            urls_file=self.urls_file.get().strip(),
            reveal_token=self.reveal_token.get(),
        )
        _save_settings(s)
        messagebox.showinfo("Saved", f"Saved settings to: {_settings_path()}")

    def _append_log(self, msg: str) -> None:
        self.log_list.insert(END, msg)
        self.log_list.yview_moveto(1)

    def _tick(self) -> None:
        try:
            while True:
                msg = self.msg_q.get_nowait()
                self._append_log(msg)
        except queue.Empty:
            pass

        self.root.after(150, self._tick)

    def _run(self) -> None:
        if self.worker and self.worker.is_alive():
            messagebox.showwarning(
                "Running",
                "Diagnostics are already running",
            )
            return

        base_url = self.base_url.get().strip()
        token = self.token.get().strip()
        if not base_url or not token:
            messagebox.showerror("Missing", "Base URL and token are required")
            return

        self.log_list.delete(0, END)
        self._append_log("Starting...")

        paths = _load_seed_urls(self.urls_file.get())
        extra_urls = _paths_to_absolute(base_url, paths)

        def cb(msg: str) -> None:
            self.msg_q.put(msg)

        def worker() -> None:
            try:
                r = run_diagnostics(
                    base_url=base_url,
                    token=token,
                    extra_urls=extra_urls,
                    max_pages=int(self.max_pages.get() or "250"),
                    timeout=float(self.timeout.get() or "12"),
                    delay_ms=int(self.delay_ms.get() or "0"),
                    script_path=self.script_path.get().strip() or None,
                    progress_cb=cb,
                )
                self.current_result = r

                out_dir = _reports_dir()
                out_dir.mkdir(parents=True, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                out_html = str(out_dir / f"diagnostics_{stamp}.html")
                out_json = str(out_dir / f"diagnostics_{stamp}.json")
                write_reports(result=r, out_html=out_html, out_json=out_json)
                self.current_html = out_html
                self.current_json = out_json

                cb(f"Base: {r.base_url}")
                cb(f"Pages tested: {len(r.pages)}")
                cb(f"OK: {r.ok_count}")
                cb(f"Failures: {r.failure_count}")
                cb(f"Wrote: {out_html}")
                cb(f"Wrote: {out_json}")
            except Exception as e:
                cb(f"ERROR: {type(e).__name__}: {e}")

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

    def _open_html(self) -> None:
        if not self.current_html:
            messagebox.showinfo("No report", "Run diagnostics first")
            return
        webbrowser.open(Path(self.current_html).as_uri())

    def _open_windows(self) -> None:
        if not self.current_result:
            messagebox.showinfo("No data", "Run diagnostics first")
            return
        show_summary_window(self.root, self.current_result)
        show_failures_window(self.root, self.current_result)
        show_pages_window(self.root, self.current_result)
        show_script_window(self.root, self.current_result)


def _reports_dir() -> Path:
    home = Path.home()
    return home / "Documents" / "PentaVision Diagnostics" / "Reports"


def tk_listbox(parent):
    import tkinter

    lb = tkinter.Listbox(parent, activestyle="none")
    lb.configure(font=("Consolas", 10))
    return lb


def _add_tree_columns(tree: ttk.Treeview, cols: list[tuple[str, int]]):
    tree["columns"] = [c[0] for c in cols]
    tree["show"] = "headings"
    for name, width in cols:
        tree.heading(name, text=name)
        tree.column(name, width=width, anchor="w")


def _copy_to_clipboard(win: Toplevel, text: str) -> None:
    win.clipboard_clear()
    win.clipboard_append(text)
    try:
        win.update_idletasks()
    except Exception:
        pass
    messagebox.showinfo("Copied", "Copied to clipboard")


def _tree_to_tsv(tree: ttk.Treeview) -> str:
    cols = list(tree["columns"])
    lines: list[str] = ["\t".join(cols)]
    for item_id in tree.get_children(""):
        values = tree.item(item_id, "values")
        row = [str(v) if v is not None else "" for v in values]
        lines.append("\t".join(row))
    return "\n".join(lines)


def show_summary_window(root: Tk, r: DiagnosticsRunResult) -> None:
    win = Toplevel(root)
    win.title("Diagnostics Summary")
    win.geometry("520x260")

    frm = ttk.Frame(win, padding=12)
    frm.pack(fill="both", expand=True)

    dur = r.finished_at - r.started_at
    rows = [
        ("Base URL", r.base_url),
        ("Pages tested", str(len(r.pages))),
        ("OK (2xx/3xx)", str(r.ok_count)),
        ("Failures", str(r.failure_count)),
        ("Duration (s)", f"{dur:.1f}"),
    ]

    def copy_all() -> None:
        txt = "\n".join(f"{k}: {v}" for (k, v) in rows)
        _copy_to_clipboard(win, txt)

    ttk.Button(frm, text="Copy all", command=copy_all).grid(
        row=0,
        column=2,
        sticky="e",
        padx=(12, 0),
    )

    for i, (k, v) in enumerate(rows):
        ttk.Label(frm, text=k).grid(row=i, column=0, sticky="w", pady=4)
        ttk.Label(frm, text=v).grid(
            row=i,
            column=1,
            sticky="w",
            padx=(12, 0),
            pady=4,
        )

    frm.grid_columnconfigure(1, weight=1)


def show_failures_window(root: Tk, r: DiagnosticsRunResult) -> None:
    win = Toplevel(root)
    win.title("Diagnostics Failures")
    win.geometry("1100x420")

    top = ttk.Frame(win, padding=(10, 10, 10, 0))
    top.pack(fill="x")

    tree = ttk.Treeview(win)
    _add_tree_columns(
        tree,
        [
            ("url", 620),
            ("status", 70),
            ("ms", 70),
            ("redirect", 240),
            ("error", 400),
        ],
    )

    def copy_all() -> None:
        _copy_to_clipboard(win, _tree_to_tsv(tree))

    ttk.Button(top, text="Copy all", command=copy_all).pack(side="left")
    tree.pack(fill="both", expand=True)

    for p in r.pages:
        if p.status is not None and 200 <= p.status < 400 and not p.error:
            continue
        tree.insert(
            "",
            END,
            values=(
                p.url,
                "" if p.status is None else str(p.status),
                "" if p.elapsed_ms is None else str(p.elapsed_ms),
                p.redirected_to or "",
                p.error or "",
            ),
        )


def show_pages_window(root: Tk, r: DiagnosticsRunResult) -> None:
    win = Toplevel(root)
    win.title("Diagnostics All Pages")
    win.geometry("1100x520")

    top = ttk.Frame(win, padding=(10, 10, 10, 0))
    top.pack(fill="x")

    tree = ttk.Treeview(win)
    _add_tree_columns(
        tree,
        [
            ("url", 620),
            ("status", 70),
            ("ms", 70),
            ("content_type", 220),
            ("redirect", 240),
            ("error", 400),
        ],
    )

    def copy_all() -> None:
        _copy_to_clipboard(win, _tree_to_tsv(tree))

    ttk.Button(top, text="Copy all", command=copy_all).pack(side="left")
    tree.pack(fill="both", expand=True)

    for p in r.pages:
        tree.insert(
            "",
            END,
            values=(
                p.url,
                "" if p.status is None else str(p.status),
                "" if p.elapsed_ms is None else str(p.elapsed_ms),
                p.content_type or "",
                p.redirected_to or "",
                p.error or "",
            ),
        )


def show_script_window(root: Tk, r: DiagnosticsRunResult) -> None:
    win = Toplevel(root)
    win.title("Diagnostics Scripted Checks")
    win.geometry("980x420")

    top = ttk.Frame(win, padding=(10, 10, 10, 0))
    top.pack(fill="x")

    tree = ttk.Treeview(win)
    _add_tree_columns(
        tree,
        [("name", 220), ("url", 520), ("ok", 60), ("message", 520)],
    )

    def copy_all() -> None:
        _copy_to_clipboard(win, _tree_to_tsv(tree))

    ttk.Button(top, text="Copy all", command=copy_all).pack(side="left")
    tree.pack(fill="both", expand=True)

    for item in r.script_results:
        tree.insert(
            "",
            END,
            values=(
                str(item.get("name") or ""),
                str(item.get("url") or ""),
                "PASS" if item.get("ok") else "FAIL",
                str(item.get("message") or ""),
            ),
        )


def main() -> int:
    root = Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    CompanionApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
