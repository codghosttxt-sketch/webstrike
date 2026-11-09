WEBSTRIKE - BEGINNER PROJECT
=============================

WHAT IT DOES
------------
WebStrike is a small educational website checker. It checks:
1. Whether a public website responds.
2. Its HTTP response code.
3. Whether a verified HTTPS/TLS connection can be made.
4. The TLS certificate expiry date (when the certificate can be verified).
5. Whether four common HTTP security headers are present.
6. It stores and displays recent scan history using SQLite.

FILES
-----
app.py           Main Python program. The HTML and CSS are included in this file.
requirements.txt Required Python packages.
README.md        Full project information and setup instructions.
webstrike.db     Created automatically after the first successful scan.

HOW TO RUN
----------
1. Install Python 3 on your laptop.
2. Open the project folder in VS Code.
3. Open the VS Code terminal.
4. Create a virtual environment:
      python -m venv venv

   Windows:
      venv\Scripts\activate

   macOS/Linux:
      source venv/bin/activate

5. Install packages:
      python -m pip install -r requirements.txt

6. Run:
      python app.py

7. Open your browser and visit:
      http://127.0.0.1:5000

8. Enter a public website such as:
      https://example.com

9. Select "View Scan History" to see recent checks.

HOW TO MAKE SIMPLE CHANGES
--------------------------
Change the page title:
  Find: <title>WebStrike - Website Security Checker</title>

Change the heading:
  Find: <h1>🛡️ WebStrike</h1>

Change the button text:
  Find: Check Website

Change the background colour:
  Find: background: #0b1220;

Add another security header:
  Find the important_headers list in scan_website().
  Add another header name as a quoted item.

IMPORTANT NOTES
---------------
- This is a beginner educational project, not a professional vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing security header does not automatically mean a website is vulnerable.
- "Reachable" means the website responded; it does not mean the site is safe.
- HTTPS and a valid certificate protect the connection but do not prove that the website itself is trustworthy.
- Redirects are not automatically followed.
- Some websites block automated requests or respond differently depending on location, so results can vary.
- Scan history is stored locally in webstrike.db, not in GitHub.
