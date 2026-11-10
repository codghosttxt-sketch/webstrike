# WebStrike

A simple student project that checks basic website security details using Python and Flask.

## Quick navigation

| What you want to change or understand | Open this file |
|---|---|
| Website scan logic, Flask routes and database | [app.py](app.py) |
| Main page headings and dashboard content | [templates/index.html](templates/index.html) |
| History page headings and layout | [templates/history.html](templates/history.html) |
| All dashboard colours, fonts, spacing and visual design | [static/css/style.css](static/css/style.css) |
| Python packages | [requirements.txt](requirements.txt) |
| Basic project tests | [test_app.py](test_app.py) |

## Project structure (recommended reading order)

```text
webstrike/
├── app.py                  # 1. Application logic and website checks
├── templates/
│   ├── index.html          # 2. Main page headings and dashboard content
│   └── history.html        # 3. Scan history headings and layout
├── static/
│   └── css/
│       └── style.css       # 4. Colours and visual design
├── requirements.txt        # 5. Required Python packages
├── test_app.py             # 6. Basic tests
├── README.md               # 7. Project guide
└── .gitignore              # Keeps temporary files out of GitHub
```

GitHub sorts files alphabetically. This guide gives you a simple order to understand and edit the project.

## Where to make common changes

- **Change colours, fonts or spacing:** edit `static/css/style.css`. Look for the `:root` colour variables near the top.
- **Change the main page title, headings or text:** edit `templates/index.html`.
- **Change Scan History headings or text:** edit `templates/history.html`.
- **Add or change a scan feature or URL route:** edit `app.py`.
- **Add a Python package:** update `requirements.txt`.

## What each part does

- **app.py:** Flask routes, website checks, certificate checks, SQLite history and delete action.
- **templates/index.html:** scanner dashboard and scan result layout.
- **templates/history.html:** saved scan list and delete buttons.
- **static/css/style.css:** dashboard appearance.
- **requirements.txt:** Python packages.
- **test_app.py:** basic tests for input validation and page routes.

## Main features

1. Checks whether a public website responds.
2. Displays the HTTP response code.
3. Checks HTTPS and the TLS certificate.
4. Checks four common security headers.
5. Saves scan records in SQLite.
6. Displays the latest scan and recent scan history.
7. Allows an individual history record to be deleted.
8. Uses a responsive dashboard with an animated radar graphic.
9. Checks for a free local port when the preferred port is occupied.

## Run the project

1. Install Python 3.
2. Open a terminal in the project folder.
3. Install packages: `python -m pip install -r requirements.txt`
4. Start the app: `python app.py`
5. In GitHub Codespaces, open the **Ports** tab and open the forwarded port (usually 5000).
6. Enter a public website and click **Check Website**.

The local database file is created automatically when scans are saved. It should not be uploaded to GitHub.

## Simple project-review explanation

WebStrike is a basic website security checker. A user enters a public website and clicks the check button. Python checks the website response, HTTPS certificate and selected security headers. Flask displays the results, and SQLite stores scan history.

## Limitations and safe use

- This is an educational checker, not a full vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing header does not automatically mean a website is vulnerable.
- A valid HTTPS certificate does not prove that a website is trustworthy.
- Scan history is stored in a local SQLite database.

## Topics demonstrated

Python functions, Flask routes, HTML templates, CSS, HTTP requests, HTTPS/TLS, response headers, input validation and SQLite.
