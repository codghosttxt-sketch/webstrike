# WebStrike

A simple student project that checks basic website security details using Python and Flask.

## Features

1. Checks whether a public website responds.
2. Shows the HTTP response code.
3. Checks HTTPS and the TLS certificate.
4. Checks four common security headers.
5. Saves scan results in a local SQLite database.
6. Shows the latest scan and the last 20 scans.
7. Uses a simple cyber-style dashboard with an original animated mascot.
8. Starts on port 5000, or checks nearby ports if that port is busy.

## Project file order

```text
webstrike/
├── app.py           # Main application and website checks
├── requirements.txt # Required Python packages
├── test_app.py      # Basic project tests
├── README.md        # Project guide
├── .gitignore       # Files Git should not upload
└── LICENSE          # Project license
```

The `webstrike.db` database is created automatically when scans are saved. It is a local data file and should not be uploaded to GitHub.

## What each file does

- **app.py:** Contains the Flask app, website checking functions, pages and scan history.
- **requirements.txt:** Lists the packages needed to run the project.
- **test_app.py:** Contains simple tests for important app features.
- **README.md:** Explains the project and how to start it.
- **.gitignore:** Keeps temporary files and the local database out of Git.
- **LICENSE:** Explains how the project can be used.

## Run the project

1. Install Python 3.
2. Open a terminal in the project folder.
3. Install the packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Start WebStrike:

   ```bash
   python app.py
   ```

5. Open the local address printed in the terminal. It normally uses `http://127.0.0.1:5000`.

6. Enter a public website and click **Check Website**. Open **Scan History** to view saved results.

## Simple explanation for a project review

WebStrike is a basic website security checker. The user enters a public website and clicks the check button. Python sends a web request and checks the response, HTTPS certificate and selected security headers. Flask displays the result, and SQLite stores the scan history.

## Limitations and safe use

- This is an educational checker, not a full vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing header does not automatically mean a website is vulnerable.
- A valid HTTPS certificate does not prove that a website is trustworthy.
- Scan history is stored locally in `webstrike.db`.

## Learning topics

Python functions, Flask routes, HTTP requests, HTTPS/TLS, response headers, input validation and SQLite.
