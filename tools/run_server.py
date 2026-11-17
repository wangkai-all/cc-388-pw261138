#!/usr/bin/env python3
"""tools/run_server.py -- start the key-rotation web service."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_rotation.webapp import serve


def main() -> int:
    parser = argparse.ArgumentParser(description="Run key rotation demo server")
    parser.add_argument("--base-dir", default="demo_env")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--log", default=None, help="optional log file path")
    args = parser.parse_args()
    serve(os.path.abspath(args.base_dir), args.host, args.port, args.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
