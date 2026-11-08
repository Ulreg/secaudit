#!/usr/bin/env python3
import argparse
import sys

import uvicorn

from app import config


def main():
    p = argparse.ArgumentParser(description="SecAuditTool - passive web security auditor")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--host", default="127.0.0.1", help="keep 127.0.0.1: the UI has no login")
    p.add_argument("--allow-private", action="store_true", help="allow scanning private/loopback IPs")
    p.add_argument("--rate", type=float, default=5.0, help="max HTTP requests per second per scan (default 5)")
    p.add_argument("--scanner-ip", default="", help="public IP shown in reports (default: auto-detected local IP)")
    args = p.parse_args()

    config.ALLOW_PRIVATE, config.RATE, config.SCANNER_IP = args.allow_private, args.rate, args.scanner_ip
    from app.api import app  # import after config is set

    print(f"[*] SecAuditTool {config.VERSION} on http://{args.host}:{args.port}  (Ctrl+C to stop)")
    if args.host not in ("127.0.0.1", "localhost"):
        print("[!] WARNING: the web UI has no authentication - do not expose it to a network.")
    try:
        uvicorn.run(app, host=args.host, port=args.port)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
