import unittest

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

    def test_home_page_loads_without_home_navigation_or_pikachu(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"WebStrike", response.data)
        self.assertNotIn(b">Home<", response.data)
        self.assertNotIn(b"Pikachu", response.data)

    def test_scan_button_and_last_scan_section_remain_available(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Check Website", response.data)
        self.assertIn(b"Last Scan", response.data)

    def test_history_page_loads_without_back_or_home_button(self):
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"WebStrike Scan History", response.data)
        self.assertNotIn(b"Back to scanner", response.data)
        self.assertNotIn(b">Home<", response.data)


if __name__ == "__main__":
    unittest.main()
