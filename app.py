from flask import Flask, request, render_template
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
    # Reject an explicitly supplied unsupported protocol instead of treating it as a hostname.
    if "://" in user_url and not user_url.startswith(("http://", "https://")):
        raise ValueError("Only HTTP and HTTPS website addresses are supported.")
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


def get_last_scan():
    """Return the most recent saved scan, or None when there is no history."""
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute("""
                SELECT id, website, website_status, https_status, scanned_at
                FROM scans
                ORDER BY id DESC
                LIMIT 1
            """).fetchone()
        except sqlite3.OperationalError:
            return None


@app.route("/", methods=["GET"])
def home():
    return render_template(
        "index.html", result=None, error=None, last_scan=get_last_scan()
    )


@app.route("/scan", methods=["POST"])
def scan():
    website = request.form.get("website", "").strip()
    try:
        result = scan_website(website)
        save_scan(result)
        return render_template(
            "index.html", result=result, error=None, last_scan=get_last_scan()
        )
    except ValueError as error:
        return render_template(
            "index.html", result=None, error=str(error), last_scan=get_last_scan()
        )


@app.route("/delete/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    """Delete one selected scan from the local history."""
    with sqlite3.connect(DATABASE) as connection:
        connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    return history()


@app.route("/history", methods=["GET"])
def history():
    """Display recent scans saved in the local SQLite database."""
    with sqlite3.connect(DATABASE) as connection:
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute("""
                SELECT id, website, website_status, https_status, scanned_at
                FROM scans
                ORDER BY id DESC
                LIMIT 20
            """).fetchall()
        except sqlite3.OperationalError:
            rows = []

    return render_template("history.html", rows=rows)


def port_is_available(port):
    """Check whether SiteCheck can use this local port."""
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
                    print("Stopped the previous SiteCheck process.")
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
                f"SiteCheck will use port {port} instead."
            )
            return port

    raise RuntimeError("No free port found between the requested port and the next 10 ports.")


if __name__ == "__main__":
    preferred_port = int(os.environ.get("PORT", "5000"))

    # First try to stop an older copy of this same SiteCheck app.
    stop_previous_webstrike(preferred_port)

    # Never terminate an unrelated application just because it uses the port.
    app_port = get_available_port(preferred_port)
    print(f"WebStrike is running on port {app_port}. Open the forwarded port in Codespaces.")
    app.run(host="0.0.0.0", port=app_port, debug=False)
