import unittest
from unittest.mock import MagicMock, patch
from web_vuln_scanner import (
    Scanner, Crawler, Reporter, Finding,
    make_session, SQL_ERROR_PATTERNS, XSS_PAYLOADS
)

class TestFinding(unittest.TestCase):

    def test_to_dict_has_all_keys(self):
        f = Finding("SQL Injection", "http://x.com", "GET", "id", "' OR 1=1", "error near")
        d = f.to_dict()
        for key in ["type", "url", "method", "parameter", "payload", "evidence", "found_at"]:
            self.assertIn(key, d)

    def test_str_representation(self):
        f = Finding("XSS", "http://x.com", "POST", "q", "<script>", "reflected")
        self.assertIn("XSS", str(f))
        self.assertIn("http://x.com", str(f))


class TestScanner(unittest.TestCase):

    def setUp(self):
        self.session = make_session()
        self.scanner = Scanner(self.session, timeout=5, delay=0)

    def test_sqli_detection_on_mysql_error(self):
        result = self.scanner._is_sqli_response(
            "Warning: mysql_fetch_array() expects parameter"
        )
        self.assertIsNotNone(result)

    def test_sqli_detection_on_syntax_error(self):
        result = self.scanner._is_sqli_response(
            "You have an error in your SQL syntax near '' at line 1"
        )
        self.assertIsNotNone(result)

    def test_sqli_no_false_positive(self):
        result = self.scanner._is_sqli_response(
            "Welcome to our website! Here is some normal content."
        )
        self.assertIsNone(result)

    def test_xss_reflected_detection(self):
        payload = "<script>alert(1)</script>"
        result  = self.scanner._is_xss_response(
            f"<html><body>{payload}</body></html>", payload
        )
        self.assertIsNotNone(result)

    def test_xss_not_detected_when_absent(self):
        result = self.scanner._is_xss_response(
            "<html><body>Safe content</body></html>",
            "<script>alert(1)</script>"
        )
        self.assertIsNone(result)

    def test_xss_partial_match_not_triggered(self):
        result = self.scanner._is_xss_response(
            "<html><body><script>legit()</script></body></html>",
            "<script>alert(1)</script>"
        )
        self.assertIsNone(result)


class TestCrawler(unittest.TestCase):

    def _make_crawler(self, base="http://example.com"):
        return Crawler(base, max_depth=2,
                       session=make_session(), timeout=5, delay=0)

    def test_in_scope_same_domain(self):
        c = self._make_crawler("http://example.com")
        self.assertTrue(c._in_scope("http://example.com/page"))

    def test_out_of_scope_different_domain(self):
        c = self._make_crawler("http://example.com")
        self.assertFalse(c._in_scope("http://other.com/page"))

    def test_normalize_url_strips_fragment(self):
        c = self._make_crawler()
        self.assertEqual(
            c._normalize_url("http://example.com/page#section"),
            "http://example.com/page"
        )

    def test_extract_links_from_html(self):
        c = self._make_crawler("http://example.com")
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        links = c._extract_links(html, "http://example.com")
        self.assertIn("http://example.com/about",   links)
        self.assertIn("http://example.com/contact", links)

    def test_extract_links_ignores_external(self):
        c = self._make_crawler("http://example.com")
        html = '<a href="http://evil.com/phish">Click</a>'
        links = c._extract_links(html, "http://example.com")
        self.assertEqual(len(links), 0)

    def test_extract_forms_get_and_post(self):
        c = self._make_crawler("http://example.com")
        html = """
            <form method="GET" action="/search">
                <input name="q" value=""><input type="submit">
            </form>
            <form method="POST" action="/login">
                <input name="user"><input name="pass" type="password">
            </form>
        """
        forms = c._extract_forms(html, "http://example.com")
        self.assertEqual(len(forms), 2)
        methods = {f["method"] for f in forms}
        self.assertIn("GET",  methods)
        self.assertIn("POST", methods)


class TestReporter(unittest.TestCase):

    def _sample_findings(self):
        return [
            Finding("SQL Injection", "http://x.com/page?id=1",
                    "GET", "id", "' OR 1=1", "mysql error near"),
            Finding("Reflected XSS", "http://x.com/search",
                    "POST", "query", "<script>alert(1)</script>", "reflected payload"),
        ]

    def test_json_export(self):
        import json, tempfile, os
        reporter = Reporter(self._sample_findings(), "http://x.com")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            reporter.export_json(path)
            with open(path) as f:
                data = json.load(f)
            self.assertEqual(data["total"], 2)
            self.assertEqual(len(data["findings"]), 2)
        finally:
            os.unlink(path)

    def test_csv_export(self):
        import csv, tempfile, os
        reporter = Reporter(self._sample_findings(), "http://x.com")
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        try:
            reporter.export_csv(path)
            with open(path) as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertIn("type", rows[0])
        finally:
            os.unlink(path)

    def test_empty_findings_report(self):
        reporter = Reporter([], "http://x.com")
        # Should not raise
        reporter.print_summary()


if __name__ == "__main__":
    unittest.main(verbosity=2)