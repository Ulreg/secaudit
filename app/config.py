"""Runtime settings shared between audit.py and the API."""
VERSION = "1.0"
ALLOW_PRIVATE = False
RATE = 5.0          # max HTTP requests per second per scan
SCANNER_IP = ""     # shown in reports so customers can recognise the traffic (auto-detected if empty)
