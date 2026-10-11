import ssl

from http.server import ThreadingHTTPServer

from xui_management.proxy import App
from xui_management.telegram_bot import Reporter


def make_server(store, panel):
    app = App(store, panel)
    host = store.data.get("listen_host") or "0.0.0.0"
    port = int(store.data.get("listen_port") or 2053)
    httpd = ThreadingHTTPServer((host, port), app.handler())
    httpd.daemon_threads = True
    cert = store.data.get("tls_cert") or ""
    key = store.data.get("tls_key") or ""
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    try:
        app.open_client_port()
    except OSError as exc:
        print("user panel port failed: {}".format(exc))
    return httpd


def serve(store, panel, start_bots=True):
    reporter = None
    if start_bots:
        reporter = Reporter(store, panel)
        reporter.start()
    httpd = make_server(store, panel)
    host, port = httpd.server_address[:2]
    scheme = "https" if store.data.get("tls_cert") and store.data.get("tls_key") else "http"
    base = store.data.get("public_base_path") or "/"
    print("xui-management listening on {}://{}:{}{}".format(scheme, host, port, base))
    print("3x-ui upstream: {}".format(store.data.get("panel_url")))
    try:
        httpd.serve_forever()
    finally:
        if reporter:
            reporter.shutdown()
        httpd.server_close()
