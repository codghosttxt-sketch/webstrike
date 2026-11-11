import tempfile
import unittest
from unittest.mock import patch

from app import app, scan_website


class WebStrikeInputTests(unittest.TestCase):
    def test_empty_address_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_website("")

    def test_unsupported_protocol_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Only HTTP and HTTPS"):
            scan_website("ftp://example.com")

    def test_embedded_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            scan_website("https://user:pass@example.com")

    def test_unusual_port_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_website("https://example.com:8080")

    def test_overlong_address_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_website("a" * 2049)


class WebStrikePageTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_patch = patch(
            "app.DATABASE", self.temp_directory.name + "/test_webstrike.db"
        )
        self.database_patch.start()

    def tearDown(self):
        self.database_patch.stop()
        self.temp_directory.cleanup()

    def test_dashboard_loads_without_top_home_or_scanner_navigation(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"WebStrike", response.data)
        self.assertIn(b"Check a website", response.data)
        self.assertNotIn(b">Home<", response.data)
        self.assertNotIn(b">Scanner<", response.data)
        self.assertNotIn(b"Pikachu", response.data)
        self.assertNotIn(b"Ready", response.data)

    def test_latest_scan_and_history_link_are_available(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Latest scan", response.data)
        self.assertIn(b"View scan history", response.data)

    def test_history_page_loads_when_database_is_empty(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan history", response.data)
        self.assertIn(b"No scan records", response.data)

    def test_scan_form_displays_validation_error(self):
        response = self.client.post("/scan", data={"website": ""})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Please enter a website address.", response.data)

    def test_successful_scan_is_saved_and_displayed(self):
        fake_result = {
            "url": "https://example.com",
            "website_status": "Reachable",
            "http_code": "200",
            "final_url": "https://example.com",
            "https_status": "Enabled",
            "certificate": {
                "status": "Valid",
                "expiry": "01 Jan 2030",
                "days_left": 100,
                "issuer": "Test issuer"
            },
            "headers": [
                {"name": "Content-Security-Policy", "present": True}
            ]
        }
        with patch("app.scan_website", return_value=fake_result):
            response = self.client.post(
                "/scan", data={"website": "https://example.com"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan results", response.data)
        self.assertIn(b"example.com", response.data)
        history_response = self.client.get("/history")
        self.assertIn(b"example.com", history_response.data)

    def test_delete_scan_removes_only_selected_record(self):
        from app import save_scan

        first = {
            "url": "https://first.example",
            "website_status": "Reachable",
            "https_status": "Enabled"
        }
        second = {
            "url": "https://second.example",
            "website_status": "Reachable",
            "https_status": "Enabled"
        }
        save_scan(first)
        save_scan(second)

        response = self.client.post("/delete/1")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"first.example", response.data)
        self.assertIn(b"second.example", response.data)


if __name__ == "__main__":
    unittest.main()
