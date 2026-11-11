# WebStrike

A beginner-friendly website security checker built with Python and Flask.

## Project structure

```text
webstrike/
├── app.py                  # Flask routes, scan logic and database
├── templates/
│   ├── index.html          # Main dashboard and scan results
│   └── history.html        # Saved scan history
├── static/
│   └── css/
│       └── style.css       # Website design and responsive layout
├── .devcontainer/
│   └── devcontainer.json   # GitHub Codespaces port settings
├── .github/
│   └── workflows/
│       └── tests.yml       # Automatic checks on GitHub
├── requirements.txt        # Python dependencies
├── test_app.py             # Project tests
├── run.sh                  # One-command setup and start
├── README.md               # Project guide
└── .gitignore              # Files that should stay out of Git
```

## Where to make changes

| Change | File |
|---|---|
| Scan logic, validation or Flask routes | `app.py` |
| Main page text, headings or scan form | `templates/index.html` |
| Scan history layout or text | `templates/history.html` |
| Colours, fonts, spacing or responsive design | `static/css/style.css` |
| Add or update Python packages | `requirements.txt` |
| Add or update tests | `test_app.py` |

The main website does not need a Home navigation button. Use the browser's Back button if you need to return from Scan History.

## Run in GitHub Codespaces

After opening the repository in Codespaces, run:

```bash
bash run.sh
```

The script installs dependencies, checks Python syntax, runs the tests and starts the Flask website. Keep the terminal running. Open the forwarded WebStrike port from the **Ports** tab.

To pull the latest GitHub changes and start in one terminal line:

```bash
git pull --ff-only origin main && bash run.sh
```

## Features

1. Checks whether a public website responds.
2. Displays its HTTP response code.
3. Checks HTTPS and the TLS certificate.
4. Checks four common security headers.
5. Saves scan records in a local SQLite database.
6. Displays the latest scan and scan history.
7. Allows an individual history record to be deleted.
8. Uses a responsive dashboard.

## How it works

The user enters a public website address and selects **Check Website**. Flask sends a normal HTTPS/HTTP request. Python checks the response, certificate and selected security headers. The results are displayed on the page and saved in SQLite.

## Safe-use notes and limitations

- This is an educational checker, not a full vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing header does not automatically mean a website is vulnerable.
- A valid HTTPS certificate does not prove that a website is trustworthy.
- The SQLite database is created locally when the first scan is saved. It is excluded from Git.

## Topics demonstrated

Python, Flask, HTML, CSS, HTTP, HTTPS/TLS, response headers, input validation, SQLite and automated testing.
