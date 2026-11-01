import argparse
import socket
import requests
import logging
import sys
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Run one shot probes of a single named host: a TCP connect check, a WHOIS lookup, and an HTTP GET request.")
    parser.add_argument("--host", help="The host to probe (e.g., google.com)", type=str)
    parser.add_argument("--port", help="The port for the TCP connect check and the HTTP GET request (default: 80)", type=int, default=80)
    parser.add_argument("--ping", help="Performs a TCP connect check on the host at the stated port (a TCP connection attempt, not an ICMP ping; the flag name is kept for compatibility)", action="store_true")
    parser.add_argument("--whois", help="Performs a WHOIS lookup on the host", action="store_true")
    parser.add_argument("--http-get", help="Performs a HTTP GET request", action="store_true")
    parser.add_argument("--timeout", help="Timeout for network operations in seconds (default: 5)", type=int, default=5)
    parser.add_argument("--log-level", help="Set the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", type=str, default="INFO")
    return parser.parse_args()


def tcp_connect_check(host, timeout, port=80):
    """
    Checks whether a TCP connection can be opened to a host on a port.
    This is a TCP connect check: it sends no ICMP echo and no data.

    Args:
        host (str): The host to check.
        timeout (int): Timeout in seconds.
        port (int): The port to connect to (default: 80).

    Returns:
        bool: True if the connection opened, False otherwise.
    """
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to the host on the stated port
        # I take only the first address getaddrinfo returns and never
        # walk the rest. The socket is IPv4, so if the first result for
        # a dual stack host is an IPv6 address the connect fails and I
        # report the host as unreachable without trying its IPv4 entry.
        addr = socket.getaddrinfo(host, port)
        sock.connect(addr[0][4])  # Connect to the first address

        logging.info(f"TCP connect check successful to {host}:{port}")
        return True
    except socket.timeout:
        logging.warning(f"TCP connect check timeout to {host}:{port}")
        return False
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname {host}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error in TCP connect check to {host}:{port}: {e}")
        return False
    finally:
        if 'sock' in locals():
            sock.close()


def ping_host(host, timeout, port=80):
    """Kept as an alias for tcp_connect_check for compatibility."""
    return tcp_connect_check(host, timeout, port)


def whois_lookup(host, timeout):
    """
    Performs a WHOIS lookup for a given host.

    Args:
        host (str): The host to perform the lookup on.
        timeout (int): Timeout in seconds.

    Returns:
        str: The WHOIS information, or None if an error occurred.
    """
    try:
        # Connect to the WHOIS server
        whois_server = "whois.iana.org" # IANA's WHOIS to discover authoritative WHOIS server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((whois_server, 43)) # Port 43 is the standard WHOIS port

        # Send the domain name
        sock.sendall((host + "\r\n").encode())

        # Receive the response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        response_text = response.decode("utf-8", errors="ignore")  # Handle encoding issues
        # Extract the specific whois server from the initial response
        if "whois:" in response_text:
            lines = response_text.splitlines()
            for line in lines:
                if line.startswith("whois:"):
                    authoritative_whois_server = line.split(":")[1].strip()
                    break
            else:
                authoritative_whois_server = None
        else:
            authoritative_whois_server = None


        if authoritative_whois_server:
            sock.close()
            # Connect to the authoritative WHOIS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((authoritative_whois_server, 43))
                sock.sendall((host + "\r\n").encode())
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                response_text = response.decode("utf-8", errors="ignore")
                logging.info(f"WHOIS lookup successful for {host}")
                return response_text
            except Exception as e:
                 # A failed referral throws away the IANA answer I already
                 # have in hand. The caller gets None and prints a plain
                 # failure, with no hint that the first hop worked.
                 logging.error(f"Error querying authoritative WHOIS server: {e}")
                 return None


        logging.info(f"WHOIS lookup successful for {host}")
        return response_text
    except socket.timeout:
        logging.warning(f"WHOIS lookup timeout for {host}")
        return None
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname {host}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error performing WHOIS lookup for {host}: {e}")
        return None
    finally:
        if 'sock' in locals():
            sock.close()


def http_get_request(host, timeout, port=80):
    """
    Performs an HTTP GET request to a given host.

    Args:
        host (str): The host to send the request to.
        timeout (int): Timeout in seconds.
        port (int): The port to request (default: 80).

    Returns:
        str: The content of the response, or None if an error occurred.
    """
    try:
        # The scheme is fixed to plain http whatever port is passed, so
        # pointing this at 443 sends a cleartext request at a TLS port
        # and the failure reads as a dead host rather than a wrong scheme.
        url = f"http://{host}:{port}"  # Assuming HTTP; consider HTTPS as well
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        logging.info(f"HTTP GET request successful to {host}")
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error performing HTTP GET request to {host}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during HTTP GET request: {e}")
        return None


def main():
    """
    Main function to parse arguments and perform network operations.
    """
    args = setup_argparse()

    # Configure logging level
    try:
        log_level = getattr(logging, args.log_level.upper())
        logging.getLogger().setLevel(log_level)
    except AttributeError:
        logging.error(f"Invalid log level: {args.log_level}. Using INFO level instead.")
        logging.getLogger().setLevel(logging.INFO)


    # Input validation: Host must be specified for most operations
    if not args.host and (args.ping or args.whois or args.http_get):
        logging.error("Host must be specified for the TCP connect check, whois, or http-get operations.")
        sys.exit(1)

    port = args.port if args.port else 80
    results = []

    if args.ping:
        ok = tcp_connect_check(args.host, args.timeout, port)
        results.append(ok)
        if ok:
            print(f"Host {args.host} is reachable on port {port} (TCP connect check).")
        else:
            print(f"Host {args.host} is not reachable on port {port} (TCP connect check).")

    if args.whois:
        whois_info = whois_lookup(args.host, args.timeout)
        results.append(whois_info is not None)
        if whois_info:
            print(whois_info)
        else:
            print(f"WHOIS lookup failed for {args.host}.")

    if args.http_get:
        http_content = http_get_request(args.host, args.timeout, port)
        results.append(http_content is not None)
        if http_content:
            print(http_content[:500] + "..." if len(http_content) > 500 else http_content) # Print only the first 500 chars
        else:
            print(f"HTTP GET request failed for {args.host}.")

    if not any([args.ping, args.whois, args.http_get]):
        print("No operation specified.  Use --help for options.")
        logging.error("No operation selected.")
        sys.exit(1)

    # Partial success exits 0. Only a run where every requested probe
    # failed is an error exit, so a script chaining on the exit code
    # cannot tell one success out of three from three out of three.
    if results and not any(results):
        logging.error("Every requested operation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()