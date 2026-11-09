from flask import Flask, request, render_template_string
import requests
import socket
import ssl
import sqlite3
import ipaddress
from urllib.parse import urlparse
from datetime import datetime
import os
import psutil

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
    user_url = (user_url or "").strip()
    if not user_url:
        raise ValueError("Please enter a website address.")
    if len(user_url) > 2048:
        raise ValueError("Website address is too long.")
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

    # Keep a safe default even when the website cannot be reached.
    final_url = user_url

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
            # HTTP header names are case-insensitive, so store them in lowercase.
            headers = {name.lower(): value for name, value in response.headers.items()}
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
            "present": header.lower() in headers
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
        body { margin: 0; font-family: Arial, sans-serif; background: #f4f6f8; color: #222; }
        .container { width: 92%; max-width: 900px; margin: 32px auto; }
        .top { display:flex; justify-content:space-between; align-items:center; gap:15px; margin-bottom:22px; }
        .top h1 { margin:0; color:#244b70; font-size:28px; }
        .top p { margin:5px 0 0; color:#626b75; }
        .nav a { display:inline-block; margin-left:8px; padding:10px 13px; border:1px solid #cbd5df; border-radius:5px; color:#244b70; text-decoration:none; background:#fff; }
        .nav a:hover { background:#eaf1f7; }
        .panel { background:#fff; border:1px solid #d9e0e6; border-radius:7px; padding:22px; margin-bottom:17px; }
        h2 { color:#244b70; font-size:19px; margin:0 0 15px; }
        form { display:flex; gap:10px; }
        input { flex:1; min-width:0; padding:12px; border:1px solid #b9c4ce; border-radius:5px; font-size:15px; background:#fff; color:#222; }
        input:focus { outline:2px solid #b7d3eb; border-color:#477da8; }
        button { padding:12px 20px; border:1px solid #244b70; border-radius:5px; background:#315f87; color:#fff; font-weight:bold; cursor:pointer; }
        button:hover { background:#244b70; }
        .grid { display:grid; grid-template-columns:repeat(2,1fr); gap:10px; }
        .item { background:#f8fafb; border:1px solid #e0e5e9; border-radius:5px; padding:13px; }
        .label { color:#626b75; font-size:13px; margin-bottom:6px; }
        .value { font-weight:bold; overflow-wrap:anywhere; }
        .good { color:#267044; } .bad { color:#a15a16; }
        .header-row { display:flex; justify-content:space-between; gap:12px; border-bottom:1px solid #e2e6ea; padding:10px 0; }
        .error { background:#fff1f0; color:#9d2d25; border:1px solid #edc7c3; border-radius:5px; padding:12px; margin-top:14px; }
        .small { color:#68727c; font-size:12px; line-height:1.5; }
        .last-scan { line-height:1.7; overflow-wrap:anywhere; }
        .empty { color:#68727c; }
        @media (max-width:600px) {
            .top { align-items:flex-start; flex-direction:column; }
            .nav a { margin:8px 8px 0 0; }
            form { flex-direction:column; }
            .grid { grid-template-columns:1fr; }
        }
    </style>
</head>
<body>
<div class="container">
    <div class="top">
        <div>
            <h1>WebStrike</h1>
            <p>Website Security Checker</p>
        </div>
        <nav class="nav">
            <a href="/">Home</a>
            <a href="/history">Scan History</a>
        </nav>
    </div>

    <div class="panel">
        <h2>Check a Website</h2>
        <form method="POST" action="/scan">
            <input type="text" name="website" placeholder="Enter a website, e.g. example.com" required maxlength="2048">
            <button type="submit">Check Website</button>
        </form>
        {% if error %}<div class="error">{{ error }}</div>{% endif %}
        <p class="small">Click Check Website whenever you want to run a scan. This tool performs basic checks on public websites; it is not a full security audit.</p>
    </div>

    <div class="panel">
        <h2>Last Scan</h2>
        {% if last_scan %}
            <div class="last-scan">
                <strong>{{ last_scan["website"] }}</strong><br>
                Website status: {{ last_scan["website_status"] }}<br>
                HTTPS status: {{ last_scan["https_status"] }}<br>
                <span class="small">Scanned at: {{ last_scan["scanned_at"] }}</span>
            </div>
        {% else %}
            <p class="empty">No scans saved yet. Enter a website above and click Check Website.</p>
        {% endif %}
        <p><a href="/history" style="color:#315f87;">View all scan history</a></p>
    </div>

    {% if result %}
    <div class="panel">
        <h2>Current Scan Results</h2>
        <div class="grid">
            <div class="item"><div class="label">Website</div><div class="value">{{ result.url }}</div></div>
            <div class="item"><div class="label">Website Status</div><div class="value">{{ result.website_status }}</div></div>
            <div class="item"><div class="label">HTTP Response Code</div><div class="value">{{ result.http_code }}</div></div>
            <div class="item"><div class="label">HTTPS Status</div><div class="value">{{ result.https_status }}</div></div>
            <div class="item"><div class="label">SSL/TLS Certificate</div><div class="value">{{ result.certificate.status }}</div></div>
            <div class="item"><div class="label">Certificate Expiry</div><div class="value">{{ result.certificate.expiry }}</div></div>
        </div>
        <h2 style="margin-top:22px;">Security Headers</h2>
        {% for header in result.headers %}
        <div class="header-row">
            <span>{{ header.name }}</span>
            {% if header.present %}<strong class="good">Present</strong>{% else %}<strong class="bad">Missing</strong>{% endif %}
        </div>
        {% endfor %}
        <p class="small">A missing header is not proof that a website is vulnerable. Header requirements depend on the website.</p>
    </div>
    {% endif %}
</div>
</body>
</html>
"""


def get_last_scan():
    """Return the most recent saved scan, or None when there is no history."""
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute("""
                SELECT website, website_status, https_status, scanned_at
                FROM scans
                ORDER BY id DESC
                LIMIT 1
            """).fetchone()
        except sqlite3.OperationalError:
            return None


@app.route("/", methods=["GET"])
def home():
    return render_template_string(
        PAGE, result=None, error=None, last_scan=get_last_scan()
    )


@app.route("/scan", methods=["POST"])
def scan():
    website = request.form.get("website", "").strip()
    try:
        result = scan_website(website)
        save_scan(result)
        return render_template_string(
            PAGE, result=result, error=None, last_scan=get_last_scan()
        )
    except ValueError as error:
        return render_template_string(
            PAGE, result=None, error=str(error), last_scan=get_last_scan()
        )


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
            * { box-sizing:border-box; }
            body { margin:0; padding:25px; font-family:Arial,sans-serif; background:#f4f6f8; color:#222; }
            main { max-width:900px; margin:20px auto; }
            h1 { color:#244b70; }
            a { color:#315f87; }
            section { background:#fff; border:1px solid #d9e0e6; border-radius:7px; padding:20px; margin-top:18px; }
            .entry { padding:14px 0; border-bottom:1px solid #e2e6ea; overflow-wrap:anywhere; line-height:1.6; }
            .entry:last-child { border-bottom:0; }
            .muted { color:#68727c; font-size:13px; }
            .empty { color:#68727c; }
        </style>
    </head>
    <body><main>
        <h1>WebStrike Scan History</h1>
        <p><a href="/">Back to scanner</a></p>
        <section>
        {% if rows %}
            {% for row in rows %}
                <div class="entry">
                    <strong>{{ row["website"] }}</strong><br>
                    Website status: {{ row["website_status"] }}<br>
                    HTTPS status: {{ row["https_status"] }}<br>
                    <span class="muted">Scanned at: {{ row["scanned_at"] }}</span>
                </div>
            {% endfor %}
        {% else %}
            <p class="empty">No scan history yet. Run your first website check.</p>
        {% endif %}
        </section>
    </main></body></html>
"""
    return render_template_string(history_page, rows=rows)


def port_is_available(port):
    """Check whether WebStrike can use this local port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
            test_socket.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def stop_previous_webstrike(port):
    """Stop only an older process running this exact app.py on the chosen port."""
    app_file = os.path.realpath(__file__)

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return False

    for connection in connections:
        if connection.laddr and connection.laddr.port == port and connection.status == psutil.CONN_LISTEN and connection.pid:
            try:
                process = psutil.Process(connection.pid)
                command = process.cmdline()
                is_this_app = any(
                    argument.lower().endswith("app.py")
                    and os.path.realpath(argument) == app_file
                    for argument in command
                )

                if is_this_app:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except psutil.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                    print("Stopped the previous WebStrike process.")
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    return False


def get_available_port(start_port):
    """Use the requested port, or the next free port if another app owns it."""
    if port_is_available(start_port):
        return start_port

    for port in range(start_port + 1, start_port + 11):
        if port_is_available(port):
            print(
                f"Port {start_port} is being used by another application. "
                f"WebStrike will use port {port} instead."
            )
            return port

    raise RuntimeError("No free port found between the requested port and the next 10 ports.")


if __name__ == "__main__":
    preferred_port = int(os.environ.get("PORT", "5000"))

    # First try to stop an older copy of this same WebStrike app.
    stop_previous_webstrike(preferred_port)

    # Never terminate an unrelated application just because it uses the port.
    app_port = get_available_port(preferred_port)
    print(f"WebStrike is available at http://127.0.0.1:{app_port}")
    app.run(host="127.0.0.1", port=app_port, debug=False)
