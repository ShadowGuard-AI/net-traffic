# net-traffic
Runs one shot probes of a single named host: a TCP connect check, a WHOIS lookup, and an HTTP GET request. The tool does not capture, monitor, or analyze network traffic; it performs only the three probes listed here, on the host the operator names. - Focused on Basic network operations

## Install
`git clone https://github.com/ShadowStrikeHQ/net-traffic`

Install the requirements with `pip install -r requirements.txt`.

## Usage
`python3 main.py --host <host> [--port <port>] [--ping] [--whois] [--http-get] [params]`

Example: `python3 main.py --host example.com --port 8080 --ping --http-get`

## The three probes
- TCP connect check (`--ping`): opens a TCP connection to the host on the stated port and reports whether it opened. This is a TCP connection attempt, not an ICMP ping: it sends no echo and no data, and a host that accepts no connection on that port is reported not reachable on that port. The `--ping` flag name is kept for compatibility.
- WHOIS lookup (`--whois`): queries whois.iana.org for the host, then the authoritative server that reply names, and prints the response.
- HTTP GET request (`--http-get`): requests `http://<host>:<port>` and prints the first 500 characters of the response body.

Results are printed to the console only. Nothing is stored, and no traffic is captured.

## Parameters
- `--host`: The host to probe (e.g., google.com).
- `--port`: The port for the TCP connect check and the HTTP GET request (default: 80).
- `--ping`: Performs the TCP connect check described above.
- `--whois`: Performs a WHOIS lookup on the host.
- `--http-get`: Performs a HTTP GET request.
- `--timeout`: Timeout for network operations in seconds (default: 5).
- `--log-level`: Set the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default: INFO.

## Exit status
The run exits with status 1 when no operation is specified, and when every requested operation fails. A run in which at least one requested operation succeeds exits with status 0.

## License
Copyright (c) ShadowStrikeHQ
