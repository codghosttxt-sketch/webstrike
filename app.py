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
import threading
import webbrowser

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
    """Check whether WebStrike can use this local port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_socket:
            test_socket.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False


def stop_previous_webstrike(start_port):
    """Stop older copies of this exact app on WebStrike's forwarded ports."""
    app_file = os.path.realpath(__file__)
    webstrike_ports = {start_port}
    stopped = False

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        print("Could not inspect existing processes; leaving them untouched.")
        return False

    checked_pids = set()
    for connection in connections:
        if (
            not connection.laddr
            or connection.laddr.port not in webstrike_ports
            or connection.status != psutil.CONN_LISTEN
            or not connection.pid
            or connection.pid in checked_pids
        ):
            continue

        checked_pids.add(connection.pid)
        try:
            process = psutil.Process(connection.pid)
            command = process.cmdline()
            is_this_app = any(
                argument.lower().endswith("app.py")
                and os.path.realpath(argument) == app_file
                for argument in command
            )

            if is_this_app and process.pid != os.getpid():
                process.terminate()
                try:
                    process.wait(timeout=3)
                except psutil.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                stopped = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if stopped:
        print("Stopped the previous WebStrike instance.")
    return stopped


def get_available_port(start_port):
    """Use only the configured WebStrike port; never create extra ports."""
    if port_is_available(start_port):
        return start_port
    raise RuntimeError(
        f"Port {start_port} is already in use. Stop the existing WebStrike "
        "server from its terminal, then run bash run.sh again."
    )


def open_local_browser(port):
    """Open WebStrike automatically on a normal local computer.

    GitHub Codespaces opens forwarded ports through .devcontainer/devcontainer.json,
    so this helper intentionally does nothing inside Codespaces.
    """
    if os.environ.get("CODESPACES") or os.environ.get("WEBSTRIKE_NO_BROWSER") == "1":
        return

    def open_page():
        try:
            webbrowser.open(f"http://127.0.0.1:{port}", new=2)
        except Exception as error:
            print(f"Browser could not be opened automatically: {error}")

    timer = threading.Timer(1.5, open_page)
    timer.daemon = True
    timer.start()


if __name__ == "__main__":
    preferred_port = int(os.environ.get("PORT", "8000"))

    # Stop only an older copy of this exact WebStrike app.
    stop_previous_webstrike(preferred_port)

    # Never terminate an unrelated application just because it uses the port.
    app_port = get_available_port(preferred_port)
    app_url = f"http://127.0.0.1:{app_port}"
    print(f"\nWebStrike is running at {app_url}", flush=True)
    print(f"Codespaces: open forwarded port {app_port} in the PORTS tab.", flush=True)
    print("Leave this terminal running. Do not type the status messages as commands.", flush=True)
    print()

    if os.environ.get("CODESPACES"):
        print("Codespaces will open the forwarded WebStrike port automatically.")
    else:
        open_local_browser(app_port)

    app.run(host="0.0.0.0", port=app_port, debug=False, use_reloader=False, threaded=True)
