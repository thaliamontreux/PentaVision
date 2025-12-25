from __future__ import annotations

import argparse
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import requests


@dataclass
class PageResult:
    url: str
    status: int | None
    elapsed_ms: int | None
    error: str | None
    redirected_to: str | None
    content_type: str | None


@dataclass
class DiagnosticsRunResult:
    base_url: str
    started_at: float
    finished_at: float
    pages: list[PageResult]
    script_results: list[dict[str, Any]]

    @property
    def ok_count(self) -> int:
        return sum(
            1
            for p in self.pages
            if p.status is not None and 200 <= p.status < 400
        )

    @property
    def failure_count(self) -> int:
        return len(self.pages) - self.ok_count


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a" and attr_map.get("href"):
            self.links.append(attr_map["href"])
        if tag.lower() in {"img", "script"} and attr_map.get("src"):
            self.links.append(attr_map["src"])
        if tag.lower() == "link" and attr_map.get("href"):
            self.links.append(attr_map["href"])


def _norm_url(url: str) -> str:
    p = urlparse(url)
    p = p._replace(fragment="")
    return urlunparse(p)


def _is_probably_html(content_type: str | None) -> bool:
    if not content_type:
        return False
    return "text/html" in content_type.lower()


def _looks_like_asset(path: str) -> bool:
    pattern = (
        r"\.(?:css|js|png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|mp4|m3u8|ts|"
        r"woff2?|ttf|eot)$"
    )
    return bool(
        re.search(
            pattern,
            path,
            re.IGNORECASE,
        )
    )


def _same_origin(base: str, url: str) -> bool:
    b = urlparse(base)
    u = urlparse(url)
    return (b.scheme, b.netloc) == (u.scheme, u.netloc)


def _discover_links(html_text: str) -> list[str]:
    parser = _LinkParser()
    try:
        parser.feed(html_text)
    except Exception:
        return []
    return parser.links


def _default_progress_cb(msg: str) -> None:
    return


def _html_report(
    *,
    base_url: str,
    started_at: float,
    finished_at: float,
    pages: list[PageResult],
    script_results: list[dict[str, Any]],
) -> str:
    ok = sum(
        1
        for p in pages
        if p.status is not None and 200 <= p.status < 400
    )
    bad = sum(1 for p in pages if p.status is None or (p.status >= 400))
    dur = finished_at - started_at

    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    rows = []
    for p in pages:
        status = "" if p.status is None else str(p.status)
        cls = (
            "ok"
            if (p.status is not None and 200 <= p.status < 400)
            else "bad"
        )
        elapsed = "" if p.elapsed_ms is None else f"{p.elapsed_ms}"
        err = "" if not p.error else esc(p.error)
        redir = "" if not p.redirected_to else esc(p.redirected_to)
        ct = "" if not p.content_type else esc(p.content_type)
        rows.append(
            f"<tr class='{cls}'>"
            f"<td class='mono'><a href='{esc(p.url)}' "
            f"target='_blank' rel='noreferrer'>{esc(p.url)}</a></td>"
            f"<td class='mono'>{status}</td>"
            f"<td class='mono'>{elapsed}</td>"
            f"<td class='small'>{ct}</td>"
            f"<td class='small'>{redir}</td>"
            f"<td class='small'>{err}</td>"
            "</tr>"
        )

    script_rows = []
    for r in script_results:
        name = esc(str(r.get("name") or ""))
        url = esc(str(r.get("url") or ""))
        ok_flag = bool(r.get("ok"))
        cls = "ok" if ok_flag else "bad"
        msg = esc(str(r.get("message") or ""))
        script_rows.append(
            f"<tr class='{cls}'>"
            f"<td class='mono'>{name}</td>"
            f"<td class='mono'><a href='{url}' target='_blank' "
            f"rel='noreferrer'>{url}</a></td>"
            f"<td class='mono'>{'PASS' if ok_flag else 'FAIL'}</td>"
            f"<td class='small'>{msg}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta
  name='viewport'
  content='width=device-width, initial-scale=1'
>
<title>PentaVision Diagnostics Report</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{
    margin: 0;
    padding: 18px;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto,
      Arial, sans-serif;
    background: #050816;
    color: #e5e7eb;
  }}
  .wrap {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ margin: 0 0 6px; font-size: 20px; }}
  .sub {{ opacity: 0.75; font-size: 13px; margin-bottom: 14px; }}
  .kpis {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin: 12px 0 18px;
  }}
  .kpi {{
    border: 1px solid rgba(148,163,184,0.18);
    border-radius: 12px;
    padding: 10px 12px;
    background: rgba(15,23,42,0.8);
  }}
  .kpi .label {{ opacity: 0.7; font-size: 12px; }}
  .kpi .val {{ font-weight: 800; font-size: 18px; margin-top: 4px; }}
  .panel {{
    border: 1px solid rgba(56,189,248,0.18);
    border-radius: 14px;
    background: rgba(2,6,23,0.45);
    padding: 12px;
    margin-top: 14px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{
    border-bottom: 1px solid rgba(148,163,184,0.18);
    padding: 7px 8px;
    vertical-align: top;
  }}
  th {{ text-align: left; font-weight: 700; color: rgba(229,231,235,0.8); }}
  tr.ok td {{ background: rgba(34,197,94,0.06); }}
  tr.bad td {{ background: rgba(248,113,113,0.06); }}
  .mono {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
      'Liberation Mono', 'Courier New', monospace;
  }}
  .small {{ font-size: 12px; opacity: 0.9; }}
  .tools {{
    display: flex;
    gap: 10px;
    align-items: center;
    margin-top: 10px;
    flex-wrap: wrap;
  }}
  input[type='text'] {{
    background: rgba(15,23,42,0.9);
    border: 1px solid rgba(148,163,184,0.22);
    border-radius: 10px;
    padding: 7px 10px;
    color: #e5e7eb;
    min-width: 260px;
  }}
  button {{
    background: linear-gradient(
      90deg,
      rgba(34,197,94,0.92),
      rgba(22,163,74,0.92)
    );
    border: none;
    border-radius: 999px;
    padding: 8px 12px;
    font-weight: 800;
    color: #06281a;
    cursor: pointer;
  }}
  button:hover {{ filter: brightness(1.05); }}
  a {{ color: rgba(125,211,252,0.95); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class='wrap'>
  <h1>PentaVision Diagnostics Report</h1>
  <div class='sub'>Base URL: <span class='mono'>{esc(base_url)}</span></div>

  <div class='kpis'>
    <div class='kpi'>
      <div class='label'>Pages tested</div>
      <div class='val'>{len(pages)}</div>
    </div>
    <div class='kpi'>
      <div class='label'>OK (2xx/3xx)</div>
      <div class='val'>{ok}</div>
    </div>
    <div class='kpi'>
      <div class='label'>Failures (4xx/5xx/errors)</div>
      <div class='val'>{bad}</div>
    </div>
    <div class='kpi'>
      <div class='label'>Duration (s)</div>
      <div class='val'>{dur:.1f}</div>
    </div>
  </div>

  <div class='panel'>
    <div class='tools'>
      <input
        id='filter'
        type='text'
        placeholder='Filter by URL / status / error text...'
      />
      <button id='copy'>Copy summary (text)</button>
      <span class='small'>
        Tip: open this HTML file in a browser for a full graphical view.
      </span>
    </div>
  </div>

  <div class='panel'>
    <h2 style='margin: 0 0 10px; font-size: 16px;'>Scripted checks</h2>
    <table id='script-table'>
      <thead>
        <tr><th>Name</th><th>URL</th><th>Result</th><th>Message</th></tr>
      </thead>
      <tbody>
        {
          ''.join(script_rows)
          if script_rows
          else (
            "<tr><td colspan='4' class='small'>"
            "No diagnostic script provided."
            "</td></tr>"
          )
        }
      </tbody>
    </table>
  </div>

  <div class='panel'>
    <h2 style='margin: 0 0 10px; font-size: 16px;'>Crawl results</h2>
    <table id='crawl-table'>
      <thead>
        <tr>
          <th>URL</th>
          <th>Status</th>
          <th>ms</th>
          <th>Content-Type</th>
          <th>Redirect</th>
          <th>Error</th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
  </div>

  <pre id='summary' class='panel mono small' style='white-space: pre-wrap;'>
Base URL: {esc(base_url)}
Pages tested: {len(pages)}
OK: {ok}
Failures: {bad}
Duration: {dur:.2f}s
Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
  </pre>
</div>

<script>
(function () {{
  var filter = document.getElementById('filter');
  var crawl = document.getElementById('crawl-table');
  var script = document.getElementById('script-table');
  var copy = document.getElementById('copy');
  var summary = document.getElementById('summary');

  function applyFilter(table) {{
    if (!table) return;
    var q = (filter.value || '').toLowerCase();
    var rows = table.querySelectorAll('tbody tr');
    rows.forEach(function (tr) {{
      var text = (tr.innerText || '').toLowerCase();
      tr.style.display = (q && text.indexOf(q) === -1) ? 'none' : '';
    }});
  }}

  filter.addEventListener('input', function () {{
    applyFilter(crawl);
    applyFilter(script);
  }});

  copy.addEventListener('click', function () {{
    var text = summary.innerText || '';
    navigator.clipboard.writeText(text).catch(function () {{}});
  }});
}})();
</script>
</body>
</html>"""


def _load_script(
    path: str | None,
) -> list[dict[str, Any]]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("checks"), list):
        return [c for c in data["checks"] if isinstance(c, dict)]
    if isinstance(data, list):
        return [c for c in data if isinstance(c, dict)]
    raise ValueError("invalid script format")


def _run_script(
    sess: requests.Session,
    base_url: str,
    checks: list[dict[str, Any]],
    timeout: float,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in checks:
        name = str(c.get("name") or c.get("path") or "check")
        method = str(c.get("method") or "GET").upper()
        path = str(c.get("path") or "/")
        url = urljoin(
            base_url.rstrip("/") + "/",
            path.lstrip("/"),
        )
        exp = c.get("expect_status")
        contains = c.get("expect_contains")
        not_contains = c.get("expect_not_contains")

        ok = True
        msg_parts: list[str] = []
        try:
            r = sess.request(
                method,
                url,
                timeout=timeout,
                allow_redirects=True,
            )
            if exp is not None and int(r.status_code) != int(exp):
                ok = False
                msg_parts.append(f"expected {exp}, got {r.status_code}")
            body = r.text or ""
            if contains and str(contains) not in body:
                ok = False
                msg_parts.append("missing expected text")
            if not_contains and str(not_contains) in body:
                ok = False
                msg_parts.append("found forbidden text")
        except Exception as e:  # noqa: BLE001
            ok = False
            msg_parts.append(f"{type(e).__name__}: {e}")

        out.append(
            {
                "name": name,
                "url": url,
                "ok": ok,
                "message": "; ".join(msg_parts) if msg_parts else "ok",
            }
        )
    return out


def crawl_site(
    sess: requests.Session,
    base_url: str,
    *,
    extra_urls: list[str] | None = None,
    max_pages: int,
    timeout: float,
    delay_ms: int,
    progress_cb: Callable[[str], None] | None = None,
) -> list[PageResult]:
    cb = progress_cb or _default_progress_cb
    start = urljoin(base_url.rstrip("/") + "/", "/")
    queue: list[str] = [_norm_url(start)]
    if extra_urls:
        for u in extra_urls:
            u2 = _norm_url(u)
            if _same_origin(base_url, u2) and u2 not in queue:
                queue.append(u2)
    seen: set[str] = set()
    results: list[PageResult] = []

    while queue and len(results) < max_pages:
        url = queue.pop(0)
        url = _norm_url(url)
        if url in seen:
            continue
        if not _same_origin(base_url, url):
            continue

        seen.add(url)

        p = urlparse(url)
        if _looks_like_asset(p.path):
            continue

        cb(
            f"fetch {len(results)+1}/{max_pages}: {url}",
        )

        t0 = time.time()
        try:
            r = sess.get(
                url,
                timeout=timeout,
                allow_redirects=False,
            )
            elapsed_ms = int(
                (time.time() - t0) * 1000,
            )
            ct = r.headers.get("Content-Type")
            redirected_to = None
            if 300 <= int(r.status_code) < 400:
                loc = r.headers.get("Location")
                if loc:
                    redirected_to = urljoin(url, loc)
            results.append(
                PageResult(
                    url=url,
                    status=int(r.status_code),
                    elapsed_ms=elapsed_ms,
                    error=None,
                    redirected_to=redirected_to,
                    content_type=ct,
                )
            )

            if 200 <= int(r.status_code) < 300 and _is_probably_html(ct):
                links = _discover_links(r.text or "")
                for href in links:
                    href = (href or "").strip()
                    if not href:
                        continue
                    if (
                        href.startswith("mailto:")
                        or href.startswith("tel:")
                    ):
                        continue
                    nxt = urljoin(url, href)
                    nxt = _norm_url(nxt)
                    if (
                        _same_origin(base_url, nxt)
                        and nxt not in seen
                    ):
                        queue.append(nxt)
        except Exception as e:  # noqa: BLE001
            dt = time.time() - t0
            elapsed_ms = int(dt * 1000)
            err_msg = f"{type(e).__name__}: {e}"
            page = PageResult(
                url=url,
                status=None,
                elapsed_ms=elapsed_ms,
                error=err_msg,
                redirected_to=None,
                content_type=None,
            )
            results.append(page)

        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    return results


def _require_diag_session(
    sess: requests.Session,
    base_url: str,
    token: str,
    timeout: float,
) -> None:
    url = urljoin(
        base_url.rstrip("/") + "/",
        "/api/diagnostics/session",
    )
    r = sess.post(
        url,
        headers={"X-PV-Diag-Token": token},
        timeout=timeout,
        allow_redirects=False,
    )
    if r.status_code != 200:
        raise RuntimeError(
            "diagnostics session failed: "
            f"{r.status_code} {r.text}",
        )


def run_diagnostics(
    *,
    base_url: str,
    token: str,
    extra_urls: list[str] | None = None,
    max_pages: int = 250,
    timeout: float = 12.0,
    delay_ms: int = 0,
    script_path: str | None = None,
    user_agent: str = "PentaVisionDiagnostics/1.0",
    progress_cb: Callable[[str], None] | None = None,
) -> DiagnosticsRunResult:
    cb = progress_cb or _default_progress_cb
    sess = requests.Session()
    sess.headers.update({"User-Agent": user_agent})

    started_at = time.time()
    cb("auth: creating diagnostics session")
    _require_diag_session(sess, base_url, token, timeout)

    checks = _load_script(script_path)
    cb(
        f"script: running {len(checks)} checks",
    )
    script_results = _run_script(sess, base_url, checks, timeout)

    cb("crawl: starting")
    pages = crawl_site(
        sess,
        base_url,
        extra_urls=extra_urls,
        max_pages=int(max_pages),
        timeout=float(timeout),
        delay_ms=int(delay_ms),
        progress_cb=cb,
    )
    finished_at = time.time()

    cb("done")
    return DiagnosticsRunResult(
        base_url=base_url,
        started_at=started_at,
        finished_at=finished_at,
        pages=pages,
        script_results=script_results,
    )


def write_reports(
    *,
    result: DiagnosticsRunResult,
    out_html: str,
    out_json: str,
) -> None:
    payload = {
        "base_url": result.base_url,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "pages": [p.__dict__ for p in result.pages],
        "script_results": result.script_results,
    }

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    html = _html_report(
        base_url=result.base_url,
        started_at=result.started_at,
        finished_at=result.finished_at,
        pages=result.pages,
        script_results=result.script_results,
    )
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)


def main(argv: Iterable[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PentaVision site crawler diagnostics")
    ap.add_argument(
        "--base-url",
        required=True,
        help="e.g. http://127.0.0.1:5000",
    )
    ap.add_argument(
        "--token",
        required=True,
        help="DIAGNOSTICS_TOKEN value",
    )
    ap.add_argument("--max-pages", type=int, default=250)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--delay-ms", type=int, default=0)
    ap.add_argument(
        "--script",
        help="Path to JSON diagnostic script (checks list)",
    )
    ap.add_argument("--out-html", default="diagnostics_report.html")
    ap.add_argument("--out-json", default="diagnostics_report.json")
    ap.add_argument("--quiet", action="store_true", help="Suppress stdout")
    args = ap.parse_args(list(argv) if argv is not None else None)

    result = run_diagnostics(
        base_url=args.base_url,
        token=args.token,
        max_pages=int(args.max_pages),
        timeout=float(args.timeout),
        delay_ms=int(args.delay_ms),
        script_path=args.script,
    )
    write_reports(
        result=result,
        out_html=args.out_html,
        out_json=args.out_json,
    )

    if not args.quiet:
        print(f"Base: {args.base_url}")
        print(f"Pages tested: {len(result.pages)}")
        print(f"OK: {result.ok_count}")
        print(f"Failures: {result.failure_count}")
        print(f"Wrote: {args.out_html}")
        print(f"Wrote: {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
