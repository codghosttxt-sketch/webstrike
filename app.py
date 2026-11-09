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
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebStrike | Website Security Lab</title>
<style>
*{box-sizing:border-box}:root{--bg:#081321;--panel:#101f32;--line:#203750;--cyan:#42d9e8;--muted:#91a5ba;--white:#edf6ff}
body{margin:0;min-height:100vh;color:var(--white);font-family:Arial,sans-serif;background:#081321;background-image:linear-gradient(#42d9e809 1px,transparent 1px),linear-gradient(90deg,#42d9e809 1px,transparent 1px),radial-gradient(ellipse at 80% 0%,#153451,transparent 42%);background-size:32px 32px,32px 32px,auto}
.container{width:92%;max-width:1040px;margin:30px auto 55px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:22px}.brand{display:flex;align-items:center;gap:13px}.brand-mark{width:43px;height:43px;display:grid;place-items:center;border:1px solid #2d6276;border-radius:13px;color:var(--cyan);background:#102b40;font-size:23px;box-shadow:0 0 24px #42d9e822}.top h1{margin:0;font-size:27px;letter-spacing:1.5px}.top h1 span{color:var(--cyan)}.top p{margin:5px 0 0;color:var(--muted);font-size:13px;letter-spacing:1px}.nav{display:flex;gap:8px;flex-wrap:wrap}.nav a{padding:10px 14px;border:1px solid var(--line);border-radius:8px;color:#c8d8e8;text-decoration:none;background:#0d1b2b;font-size:13px}.nav a:hover{border-color:var(--cyan);color:var(--cyan)}
.hero{display:grid;grid-template-columns:1.5fr .8fr;align-items:center;gap:20px;padding:27px;margin-bottom:17px;border:1px solid #24435b;border-radius:15px;background:linear-gradient(120deg,#10253a,#0d1b2b 70%);position:relative;overflow:hidden}.eyebrow{color:var(--cyan);font-size:11px;letter-spacing:2px;font-weight:bold}.hero h2{margin:10px 0;font-size:clamp(24px,4vw,36px);line-height:1.12}.hero p{color:var(--muted);line-height:1.6;max-width:510px;margin:0;font-size:14px}
.mascot-wrap{display:flex;justify-content:center;align-items:center;min-height:150px;position:relative}.mascot{width:122px;height:105px;position:relative;background:linear-gradient(145deg,#ffe98a,#ffc83d);border:2px solid #f6b92d;border-radius:48% 48% 43% 43%;box-shadow:0 12px 28px #0005;animation:float 3s ease-in-out infinite}.ear{position:absolute;width:24px;height:54px;top:-37px;background:linear-gradient(#ffd95c 72%,#4a3b32 73%);border:2px solid #f2b832;border-radius:90% 15% 50% 50%;z-index:-1}.ear.left{left:10px;transform:rotate(-25deg);animation:earL 4s infinite}.ear.right{right:10px;transform:rotate(25deg) scaleX(-1);animation:earR 4s infinite}.eye{position:absolute;top:39px;width:9px;height:13px;border-radius:50%;background:#263342;animation:blink 4.5s infinite}.eye.left{left:31px}.eye.right{right:31px}.cheek{position:absolute;top:59px;width:19px;height:15px;border-radius:50%;background:#ff795d;box-shadow:0 0 13px #ff795d77}.cheek.left{left:13px}.cheek.right{right:13px}.mouth{position:absolute;left:50%;top:57px;width:13px;height:9px;border-bottom:2px solid #75452d;border-radius:50%;transform:translateX(-50%)}.spark{position:absolute;color:#ffd45a;font-size:24px;animation:spark 1.8s infinite}.spark.one{top:4px;right:4px}.spark.two{bottom:7px;left:3px;animation-delay:.8s}
@keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-9px) rotate(2deg)}}@keyframes blink{0%,43%,47%,100%{transform:scaleY(1)}45%{transform:scaleY(.12)}}@keyframes earL{0%,85%,100%{transform:rotate(-25deg)}90%{transform:rotate(-39deg)}}@keyframes earR{0%,85%,100%{transform:rotate(25deg) scaleX(-1)}90%{transform:rotate(39deg) scaleX(-1)}}@keyframes spark{0%,100%{opacity:.25;transform:scale(.7)}50%{opacity:1;transform:scale(1.2) rotate(25deg)}}
.panel{background:linear-gradient(145deg,#112238,#0e1b2b);border:1px solid var(--line);border-radius:13px;padding:22px;margin-bottom:17px;box-shadow:0 10px 30px #0002}h3{color:var(--white);font-size:17px;margin:0 0 15px}.tag{color:var(--cyan);font-size:10px;letter-spacing:1.7px;margin-bottom:8px;font-weight:bold}form{display:flex;gap:10px}input{flex:1;min-width:0;padding:14px;border:1px solid #2b4962;border-radius:8px;font-size:15px;background:#091727;color:var(--white)}input::placeholder{color:#6f879e}input:focus{outline:2px solid #42d9e855;border-color:var(--cyan)}button{padding:13px 21px;border:1px solid #55e1ec;border-radius:8px;background:linear-gradient(120deg,#1d9fb4,#16788f);color:#04131e;font-weight:bold;cursor:pointer}button:hover{filter:brightness(1.13)}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px}.item{background:#0a1929;border:1px solid #203750;border-radius:9px;padding:14px;position:relative;overflow:hidden}.item:before{content:"";position:absolute;left:0;top:0;width:3px;height:100%;background:var(--cyan)}.label{color:var(--muted);font-size:11px;letter-spacing:.8px;margin-bottom:8px;text-transform:uppercase}.value{font-weight:bold;overflow-wrap:anywhere;font-size:14px}.good{color:#62e6ad}.bad{color:#ffc46a}.header-row{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid #203750;padding:12px 2px;font-size:13px}.error{background:#3a1c27;color:#ffb6b6;border:1px solid #87404a;border-radius:8px;padding:12px;margin-top:14px}.small{color:var(--muted);font-size:12px;line-height:1.6}.last-scan{line-height:1.9;overflow-wrap:anywhere;color:#c8d8e8}.empty{color:var(--muted)}.scan-line{height:3px;background:#203750;border-radius:5px;overflow:hidden;margin-top:17px}.scan-line span{display:block;width:35%;height:100%;background:var(--cyan);box-shadow:0 0 12px var(--cyan);animation:scan 3s ease-in-out infinite alternate}@keyframes scan{from{transform:translateX(0)}to{transform:translateX(185%)}}.footer{text-align:center;color:#617b94;font-size:11px;padding:8px;letter-spacing:1px}
@media(max-width:650px){.top{align-items:flex-start;flex-direction:column}.hero{grid-template-columns:1fr;text-align:center}.hero p{margin:auto}.mascot-wrap{min-height:130px}form{flex-direction:column}.grid{grid-template-columns:1fr}.panel{padding:17px}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
</style></head><body><div class="container">
<header class="top"><div class="brand"><div class="brand-mark">⌁</div><div><h1>WEB<span>STRIKE</span></h1><p>WEBSITE SECURITY LAB / 01</p></div></div><nav class="nav"><a href="/">⌂ Home</a><a href="/history">◷ Scan History</a></nav></header>
<section class="hero"><div><div class="eyebrow">● SYSTEM READY</div><h2>Check your website.<br>Know your security.</h2><p>A simple educational checker for website availability, HTTPS certificates and important security headers.</p><div class="scan-line"><span></span></div></div><div class="mascot-wrap" aria-label="Original animated yellow electric mascot"><span class="spark one">✦</span><span class="spark two">ϟ</span><div class="mascot" aria-hidden="true"><div class="ear left"></div><div class="ear right"></div><div class="eye left"></div><div class="eye right"></div><div class="cheek left"></div><div class="cheek right"></div><div class="mouth"></div></div></div></section>
<section class="panel"><div class="tag">01 / TARGET INPUT</div><h3>Website Scanner</h3><form method="POST" action="/scan"><input type="text" name="website" placeholder="Enter a website, e.g. example.com" required maxlength="2048"><button type="submit">⚡ Check Website</button></form>{% if error %}<div class="error">{{ error }}</div>{% endif %}<p class="small">A scan starts only when you click the button. Checks are limited to public websites; this is not a full security audit.</p></section>
<section class="panel"><div class="tag">02 / RECENT ACTIVITY</div><h3>Last Scan</h3>{% if last_scan %}<div class="last-scan"><strong>{{ last_scan["website"] }}</strong><br>Website status: {{ last_scan["website_status"] }}<br>HTTPS status: {{ last_scan["https_status"] }}<br><span class="small">Scanned at: {{ last_scan["scanned_at"] }}</span></div>{% else %}<p class="empty">No scans saved yet. Enter a website above and click Check Website.</p>{% endif %}<p><a href="/history" style="color:#42d9e8;text-decoration:none;">Open scan history →</a></p></section>
{% if result %}<section class="panel"><div class="tag">03 / SCAN REPORT</div><h3>Current Scan Results</h3><div class="grid"><div class="item"><div class="label">Website</div><div class="value">{{ result.url }}</div></div><div class="item"><div class="label">Website Status</div><div class="value">{{ result.website_status }}</div></div><div class="item"><div class="label">HTTP Response Code</div><div class="value">{{ result.http_code }}</div></div><div class="item"><div class="label">HTTPS Status</div><div class="value">{{ result.https_status }}</div></div><div class="item"><div class="label">SSL/TLS Certificate</div><div class="value">{{ result.certificate.status }}</div></div><div class="item"><div class="label">Certificate Expiry</div><div class="value">{{ result.certificate.expiry }}</div></div></div><h3 style="margin-top:23px">Security Headers</h3>{% for header in result.headers %}<div class="header-row"><span>{{ header.name }}</span>{% if header.present %}<strong class="good">✓ Present</strong>{% else %}<strong class="bad">! Missing</strong>{% endif %}</div>{% endfor %}<p class="small">A missing header is not proof that a website is vulnerable. Header requirements depend on the website.</p></section>{% endif %}
<div class="footer">WEBSTRIKE // LEARN • CHECK • IMPROVE</div></div></body></html>
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
    <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>WebStrike | Scan History</title>
    <style>*{box-sizing:border-box}body{margin:0;padding:25px;font-family:Arial,sans-serif;background:#081321;color:#edf6ff;background-image:linear-gradient(#42d9e809 1px,transparent 1px),linear-gradient(90deg,#42d9e809 1px,transparent 1px);background-size:32px 32px}main{max-width:900px;margin:20px auto}h1{color:#42d9e8;letter-spacing:1px}a{color:#42d9e8;text-decoration:none}section{background:#101f32;border:1px solid #203750;border-radius:13px;padding:20px;margin-top:18px}.entry{padding:15px 0;border-bottom:1px solid #203750;overflow-wrap:anywhere;line-height:1.7}.entry:last-child{border-bottom:0}.muted,.empty{color:#91a5ba;font-size:13px}.back{display:inline-block;padding:9px 13px;border:1px solid #29475e;border-radius:8px}</style></head>
    <body><main><p class="muted">WEBSTRIKE / ACTIVITY LOG</p><h1>Scan History</h1><p><a class="back" href="/">← Back to scanner</a></p><section>
    {% if rows %}{% for row in rows %}<div class="entry"><strong>{{ row["website"] }}</strong><br>Website status: {{ row["website_status"] }}<br>HTTPS status: {{ row["https_status"] }}<br><span class="muted">Scanned at: {{ row["scanned_at"] }}</span></div>{% endfor %}{% else %}<p class="empty">No scan history yet. Run your first website check.</p>{% endif %}
    </section></main></body></html>
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
