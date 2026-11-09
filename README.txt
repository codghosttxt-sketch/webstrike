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

PROJECT FILES
-------------
app.py           Main Python program. HTML and CSS are included.
test_app.py      Automated tests for basic input validation and pages.
requirements.txt Python packages.
README.md        Full project information and setup instructions.
webstrike.db     Created automatically after the first successful scan.

WINDOWS / VS CODE TERMINAL
--------------------------
1. Open the project folder in VS Code.
2. Open Terminal -> New Terminal.
3. Create a virtual environment:
      python -m venv .venv
4. Activate it:
      .venv\Scripts\Activate.ps1
5. Install packages:
      python -m pip install -r requirements.txt
6. Run tests:
      python -m unittest -v
7. Start the app:
      python app.py
8. Open this address in your browser:
      http://127.0.0.1:5000

If PowerShell blocks activation, use .venv\Scripts\python.exe instead of python.

IMPORTANT NOTES
---------------
- This is a beginner educational project, not a professional vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing security header does not automatically mean a website is vulnerable.
- "Reachable" means the website responded; it does not mean the site is safe.
- HTTPS and a valid certificate protect the connection but do not prove that the website itself is trustworthy.
- Redirects are not automatically followed.
- Scan history is stored locally in webstrike.db, not in GitHub.
