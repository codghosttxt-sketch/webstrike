# SiteCheck

A simple student project that checks basic website security details using Python and Flask.

## Quick navigation

| If you want to... | Open this file |
|---|---|
| See the complete application and change its features | [app.py](app.py) |
| See which Python packages are required | [requirements.txt](requirements.txt) |
| Check the basic project tests | [test_app.py](test_app.py) |
| Understand or run the project | [README.md](README.md) |

## Project files (easy order)

```text
sitecheck/
├── app.py            # 1. Main application, scanner and web pages
├── requirements.txt  # 2. Python packages needed by the app
├── test_app.py       # 3. Basic tests for important features
├── README.md         # 4. Project guide and instructions
└── .gitignore        # 5. Keeps temporary files out of GitHub
```

GitHub displays files in its own alphabetical order. The numbered list above is the recommended order to understand the project.

The `webstrike.db` database is created automatically when scans are saved. It is local application data and should not be uploaded to GitHub.

## What each file does

- **app.py:** Contains the Flask application, website checks, dashboard, scan history and delete-scan route.
- **requirements.txt:** Lists the Python packages required by the application.
- **test_app.py:** Contains basic tests for input validation and page routes.
- **README.md:** Explains the project and how to use it.
- **.gitignore:** Prevents temporary files and the local database from being committed.

## Main features

1. Checks whether a public website responds.
2. Displays the HTTP response code.
3. Checks HTTPS and the TLS certificate.
4. Checks four common security headers.
5. Saves scan records in SQLite.
6. Displays the latest scan and recent scan history.
7. Allows an individual history record to be deleted.
8. Uses a clean dashboard with a simple animated radar graphic.
9. Checks for a free local port when the preferred port is occupied.

## Run the project

1. Install Python 3.
2. Open a terminal in the project folder.
3. Install the required packages:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Start the application:

   ```bash
   python app.py
   ```

5. Open the local address printed in the terminal.
6. Enter a public website and click **Check Website**. Open **Scan History** to view or delete saved records.

## Simple explanation for a project review

SiteCheck is a basic website security checker. The user enters a public website and clicks the check button. Python checks the website response, HTTPS certificate and selected security headers. Flask displays the results, and SQLite stores the scan history.

## Limitations and safe use

- This is an educational checker, not a full vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing header does not automatically mean a website is vulnerable.
- A valid HTTPS certificate does not prove that a website is trustworthy.
- Scan history is stored in the local `webstrike.db` database.

## Topics demonstrated

Python functions, Flask routes, HTTP requests, HTTPS/TLS, response headers, input validation and SQLite.
