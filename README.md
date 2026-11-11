# WebStrike

WebStrike is a small educational website security checker built with Python and Flask. It checks public website availability, HTTPS certificate information and selected HTTP security headers.

## Project structure

```text
webstrike/
├── app.py
├── run.sh
├── requirements.txt
├── test_app.py
├── README.md
├── .gitignore
├── templates/
│   ├── index.html
│   └── history.html
├── static/
│   └── css/
│       └── style.css
├── .devcontainer/
│   └── devcontainer.json
└── .github/
    └── workflows/
        └── tests.yml
```

## Where to edit

| If you need to change... | Edit this file |
|---|---|
| Website scan logic or validation | `app.py` |
| Main page headings, labels or buttons | `templates/index.html` |
| Scan history page | `templates/history.html` |
| Colours, spacing, fonts or layout | `static/css/style.css` |
| Python packages | `requirements.txt` |
| Automated checks | `test_app.py` |

**Change colours:** Open `static/css/style.css` and edit the variables at the top under `:root`, such as `--accent`, `--page` and `--text`.

**Change a heading or button label:** Open the relevant HTML template and edit its text. Keep the HTML tags, `name="website"`, form actions (`/scan`, `/delete/...`) and Jinja template markers (`{% ... %}` / `{{ ... }}`) unchanged unless you also update the Flask route. For a visual-only change, edit CSS instead of Python.

## Safe change process (use this before showing the project)

1. Change one small thing at a time.
2. Save the file.
3. Run `python -m py_compile app.py test_app.py && python -m unittest discover -v` in the terminal.
4. If every test passes, start the app with `bash run.sh` and check the page in the forwarded port.
5. Commit the change only after the page works.

The automated GitHub Actions checks run the same syntax and unit tests whenever you push a commit or open a pull request. These checks catch many mistakes, but always open the website and test the feature you changed too.

## Run in GitHub Codespaces

Run this command in the terminal:

```bash
bash run.sh
```

The script installs dependencies, checks Python syntax, runs unit tests and starts the website. Port 8000 is preferred; if it is busy, the application checks the next ten ports. Keep the terminal open. In the **PORTS** tab, open the port printed by the application.

To update your workspace first while preserving local changes:

```bash
git stash push -u -m "Save local WebStrike workspace changes" && git pull --ff-only origin main && bash run.sh
```

## Features

1. Checks whether a public website responds.
2. Shows its HTTP response code.
3. Checks HTTPS and TLS certificate information.
4. Checks four common security headers.
5. Saves scan history in a local SQLite database.
6. Shows the latest scan and scan history.
7. Allows an individual history record to be deleted.
8. Uses a responsive layout.

## How it works

The browser sends the entered website address to a Flask route. Python validates the address and checks that it resolves to a public IP address. The application makes a normal web request, reads the response headers and checks the TLS certificate. Flask sends the results to the HTML template, and SQLite stores a scan-history record.

## Limitations and safe use

- This is an educational checker, not a full vulnerability scanner.
- Only check public websites you are allowed to assess.
- A missing security header is not automatically proof of a vulnerability.
- A valid TLS certificate does not prove that a website is trustworthy.
- Scan history is stored in the local `webstrike.db` file and is not committed to Git.
