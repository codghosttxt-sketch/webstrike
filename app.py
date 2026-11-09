from flask import Flask, request, render_template_string
import requests
import socket
import ssl
import sqlite3
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)
DATABASE = "webstrike.db"

# Important security check: only allow public internet addresses.
def is_public_website(hostname):
    try:
        addresses = socket.getaddrinfo(hostname, None)
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            if not ip.is_global:
                return False
        return len(addresses) > 0
    except Exception:
        return False


def check_certificate(hostname):
    """Try a normal, certificate-verified TLS connection on port 443."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                certificate = secure_sock.getpeercert()

        expiry_text = certificate.get("notAfter", "")
        expiry_date = datetime.strptime(
            expiry_text, "%b %d %H:%M:%S %Y %Z"
        )
        days_left = (expiry_date - datetime.utcnow()).days

        return {
            "status": "Valid",
            "expiry": expiry_date.strftime("%d %b %Y"),
            "days_left": days_left,
            "issuer": certificate.get("issuer", "Not available")
        }
    except ssl.SSLCertVerificationError:
        return {
            "status": "Invalid or untrusted",
            "expiry": "Not available",
            "days_left": "Not available",
            "issuer": "Not available"
        }
    except Exception:
        return {
            "status": "Could not check",
            "expiry": "Not available",
            "days_left": "Not available",
            "issuer": "Not available"
        }


def scan_website(user_url):
    # Add https:// if the user leaves out the protocol.
    if not user_url.startswith(("http://", "https://")):
        user_url = "https://" + user_url

    parsed = urlparse(user_url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Please enter a valid website URL.")

    hostname = parsed.hostname

    # Keep input simple: no embedded credentials or unusual ports.
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Please enter a valid website address.")

    if parsed.username or parsed.password:
        raise ValueError("Do not include a username or password in the website address.")

    if port not in (None, 80, 443):
        raise ValueError("Please use the normal website ports (80 or 443).")

    if not is_public_website(hostname):
        raise ValueError("Please enter a publicly accessible website.")

    # Check whether the submitted address responds.
    try:
        with requests.get(
            user_url,
            timeout=8,
            allow_redirects=False,
            verify=True,
            stream=True,
            headers={"User-Agent": "WebStrike-Educational-Checker/1.0"}
        ) as response:
            website_status = "Reachable"
            http_code = str(response.status_code)
            headers = dict(response.headers)
    except requests.exceptions.SSLError:
        website_status = "Certificate / HTTPS error"
        http_code = "Not available"
        final_url = user_url
        headers = {}
    except requests.exceptions.RequestException:
        website_status = "Not reachable"
        http_code = "Not available"
        final_url = user_url
        headers = {}

    # Check HTTPS on the website's hostname, even if user entered HTTP.
    certificate = check_certificate(hostname)

    if certificate["status"] == "Valid":
        https_status = "Enabled"
    elif certificate["status"] == "Invalid or untrusted":
        https_status = "Connection found, certificate problem"
    else:
        https_status = "Not available"

    important_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options"
    ]

    header_results = []
    for header in important_headers:
        header_results.append({
            "name": header,
            "present": header in headers
        })

    return {
        "url": user_url,
        "website_status": website_status,
        "http_code": http_code,
        "final_url": final_url,
        "https_status": https_status,
        "certificate": certificate,
        "headers": header_results
    }


def save_scan(result):
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT,
                website_status TEXT,
                https_status TEXT,
                scanned_at TEXT
            )
        """)
        connection.execute("""
            INSERT INTO scans (website, website_status, https_status, scanned_at)
            VALUES (?, ?, ?, ?)
        """, (
            result["url"],
            result["website_status"],
            result["https_status"],
            datetime.now().strftime("%d-%m-%Y %H:%M")
        ))


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebStrike - Website Security Checker</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #0b1220;
            color: #edf3ff;
        }
        .container { width: 90%; max-width: 900px; margin: 45px auto; }
        .top { text-align: center; margin-bottom: 28px; }
        .top h1 { color: #54b7ff; margin-bottom: 8px; }
        .top p { color: #b8c5d9; }
        .panel {
            background: #151f32;
            border: 1px solid #293750;
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 20px;
        }
        form { display: flex; gap: 10px; }
        input {
            flex: 1;
            min-width: 0;
            padding: 14px;
            border: 1px solid #40516e;
            border-radius: 8px;
            background: #0b1220;
            color: white;
            font-size: 15px;
        }
        button {
            padding: 14px 22px;
            border: 0;
            border-radius: 8px;
            background: #1687dc;
            color: white;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { background: #0872c3; }
        h2 { color: #54b7ff; font-size: 20px; }
        .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
        .item {
            background: #0e1829;
            border: 1px solid #293750;
            border-radius: 10px;
            padding: 15px;
        }
        .label { color: #9fb0c8; font-size: 13px; margin-bottom: 7px; }
        .value { font-weight: bold; overflow-wrap: anywhere; }
        .good { color: #56dfa0; }
        .bad { color: #ffbd69; }
        .header-row {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            border-bottom: 1px solid #293750;
            padding: 10px 0;
        }
        .error {
            background: #4b2028;
            color: #ffd9df;
            border-radius: 8px;
            padding: 13px;
            margin-top: 15px;
        }
        .small { color: #9fb0c8; font-size: 12px; line-height: 1.5; }
        @media (max-width: 600px) {
            form { flex-direction: column; }
            .grid { grid-template-columns: 1fr; }
            .container { margin: 25px auto; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="top">
        <h1>🛡️ WebStrike</h1>
        <p>Website Security Analysis and HTTPS Checker</p>
        <p><a href="/history" style="color:#54b7ff;">View Scan History</a></p>
    </div>

    <div class="panel">
        <h2>Check a Website</h2>
        <form method="POST" action="/scan">
            <input type="text" name="website" placeholder="Enter a website, e.g. example.com" required>
            <button type="submit">Check Website</button>
        </form>
        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}
        <p class="small">Use this educational tool only with public websites. Results are basic checks, not a full security audit.</p>
    </div>

    {% if result %}
    <div class="panel">
        <h2>Scan Results</h2>
        <div class="grid">
            <div class="item">
                <div class="label">Website</div>
                <div class="value">{{ result.url }}</div>
            </div>
            <div class="item">
                <div class="label">Website Status</div>
                <div class="value">{{ result.website_status }}</div>
            </div>
            <div class="item">
                <div class="label">HTTP Response Code</div>
                <div class="value">{{ result.http_code }}</div>
            </div>
            <div class="item">
                <div class="label">HTTPS Status</div>
                <div class="value">{{ result.https_status }}</div>
            </div>
            <div class="item">
                <div class="label">SSL/TLS Certificate</div>
                <div class="value">{{ result.certificate.status }}</div>
            </div>
            <div class="item">
                <div class="label">Certificate Expiry</div>
                <div class="value">{{ result.certificate.expiry }}</div>
            </div>
        </div>

        <h2 style="margin-top:25px;">Security Headers</h2>
        {% for header in result.headers %}
        <div class="header-row">
            <span>{{ header.name }}</span>
            {% if header.present %}
                <strong class="good">Present</strong>
            {% else %}
                <strong class="bad">Missing</strong>
            {% endif %}
        </div>
        {% endfor %}
        <p class="small">A missing header is not proof that a website is vulnerable. Header requirements depend on the website.</p>
    </div>
    {% endif %}
</div>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def home():
    return render_template_string(PAGE, result=None, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    website = request.form.get("website", "").strip()
    try:
        result = scan_website(website)
        save_scan(result)
        return render_template_string(PAGE, result=result, error=None)
    except ValueError as error:
        return render_template_string(PAGE, result=None, error=str(error))


@app.route("/history", methods=["GET"])
def history():
    """Display recent scans saved in the local SQLite database."""
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("""
                SELECT website, website_status, https_status, scanned_at
                FROM scans
                ORDER BY id DESC
                LIMIT 20
            """).fetchall()
        except sqlite3.OperationalError:
            rows = []

    history_page = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>WebStrike - Scan History</title>
        <style>
            body { margin:0; padding:25px; font-family:Arial,sans-serif;
                   background:#0b1220; color:#edf3ff; }
            main { max-width:900px; margin:25px auto; }
            section { background:#151f32; border:1px solid #293750;
                      border-radius:12px; padding:20px; margin-bottom:12px; }
            h1 { color:#54b7ff; }
            a { color:#54b7ff; }
            .entry { padding:14px 0; border-bottom:1px solid #293750;
                     overflow-wrap:anywhere; }
            .muted { color:#9fb0c8; font-size:13px; }
        </style>
    </head>
    <body><main>
        <h1>WebStrike Scan History</h1>
        <p><a href="/">← Back to scanner</a></p>
        <section>
        {% if rows %}
            {% for row in rows %}
                <div class="entry">
                    <strong>{{ row["website"] }}</strong>
                    <p>{{ row["website_status"] }} · {{ row["https_status"] }}</p>
                    <span class="muted">{{ row["scanned_at"] }}</span>
                </div>
            {% endfor %}
        {% else %}
            <p>No scan history yet. Run your first website check.</p>
        {% endif %}
        </section>
    </main></body></html>
    """
    return render_template_string(history_page, rows=rows)


if __name__ == "__main__":
    app.run(debug=False)
