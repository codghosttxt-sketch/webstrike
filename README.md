# 🛡️ WebStrike

A beginner-friendly website security and HTTPS checker built with Python and Flask.

## What it checks

- Whether a public website responds to an HTTP request
- The HTTP response code
- Whether a verified HTTPS/TLS connection is available
- TLS certificate expiry date (when the certificate can be verified)
- Four common HTTP security headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
- The most recent scan shown on the home page
- The 20 most recent scans stored locally with SQLite

## Project files

| File | Purpose |
| --- | --- |
| `app.py` | Main Flask application, website checks and history page |
| `requirements.txt` | Python package dependencies |
| `README.md` | Project documentation |
| `README.txt` | Additional beginner setup notes |
| `webstrike.db` | Local scan database, created automatically |

## Run on Windows

1. Install Python 3.
2. Download or clone this repository.
3. Open the project folder in VS Code.
4. Open **Terminal → New Terminal**.
5. Create a virtual environment (recommended):

   ```powershell
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, you can skip activation and use the Python executable inside `.venv\Scripts\` directly.

6. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

7. Start the app:

   ```powershell
   python app.py
   ```

8. Open **http://127.0.0.1:5000** in your browser.
9. Enter a public website, such as `https://example.com`.
10. The home page shows your **Last Scan** after a scan is completed.
11. Select **Scan History** to see the 20 most recent saved scans.
12. To scan again, enter a website and click **Check Website**. Scans only run when you submit the form.

## Safety and limitations

- Use this educational tool only to check public websites you are permitted to assess.
- This is a basic checker, not a full vulnerability scanner or penetration-testing tool.
- A missing security header does not automatically mean a website is vulnerable.
- A reachable website or valid HTTPS certificate does not prove that the website is trustworthy.
- Redirects are not automatically followed by the checker. This avoids silently sending a request to a different destination.
- Some websites block automated requests or respond differently depending on location, so results may vary.
- Scan history is stored locally in `webstrike.db`; it is not uploaded to GitHub.

## Learning goals

This project demonstrates beginner concepts in Python, Flask routes, HTTP requests, TLS certificates, HTTP response headers, input validation and SQLite databases.

## License

MIT
