"""Start the platform:  python server.py [--port 8767] [--open] [--data-dir data] [--rows 5000]
Listens on 127.0.0.1 only. Spark is used by the data lake only when PySpark and Java are installed."""
import argparse
import logging
import threading
import webbrowser

from securehub.app import create_app


def main(argv=None):
    ap = argparse.ArgumentParser(description="SSAD TP3 - SecureHub: access control platform")
    ap.add_argument("--port", type=int, default=8767)
    ap.add_argument("--open", action="store_true", help="open the browser")
    ap.add_argument("--data-dir", default=None, help="keep the audit log and RSA keys in this folder")
    ap.add_argument("--rows", type=int, default=5000, help="rows of the demo data lake")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    url = "http://127.0.0.1:%d/" % a.port
    print("SecureHub running at %s  (Ctrl+C to stop)" % url)
    if a.open:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    create_app({"DATA_DIR": a.data_dir, "LAKE_ROWS": a.rows}).run(host="127.0.0.1", port=a.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
