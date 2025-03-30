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
    parser = argparse.ArgumentParser(description="Monitor and analyze basic network traffic patterns.")
    parser.add_argument("--host", help="The host to monitor (e.g., google.com)", type=str)
    parser.add_argument("--port", help="The port to monitor (e.g., 80)", type=int)
    parser.add_argument("--ping", help="Pings the host", action="store_true")
    parser.add_argument("--whois", help="Performs a WHOIS lookup on the host", action="store_true")
    parser.add_argument("--http-get", help="Performs a HTTP GET request", action="store_true")
    parser.add_argument("--timeout", help="Timeout for network operations in seconds (default: 5)", type=int, default=5)
    parser.add_argument("--log-level", help="Set the log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", type=str, default="INFO")
    return parser.parse_args()


def ping_host(host, timeout):
    """
    Pings a host to check its reachability.

    Args:
        host (str): The host to ping.
        timeout (int): Timeout in seconds.

    Returns:
        bool: True if the host is reachable, False otherwise.
    """
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Connect to the host
        addr = socket.getaddrinfo(host, 80)  # Using port 80 for ping
        sock.connect(addr[0][4])  # Connect to the first address

        logging.info(f"Ping successful to {host}")
        return True
    except socket.timeout:
        logging.warning(f"Ping timeout to {host}")
        return False
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname {host}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error pinging {host}: {e}")
        return False
    finally:
        if 'sock' in locals():
            sock.close()


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


def http_get_request(host, timeout):
    """
    Performs an HTTP GET request to a given host.

    Args:
        host (str): The host to send the request to.
        timeout (int): Timeout in seconds.

    Returns:
        str: The content of the response, or None if an error occurred.
    """
    try:
        url = f"http://{host}"  # Assuming HTTP; consider HTTPS as well
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
        logging.error("Host must be specified for ping, whois, or http-get operations.")
        sys.exit(1)

    if args.ping:
        if ping_host(args.host, args.timeout):
            print(f"Host {args.host} is reachable.")
        else:
            print(f"Host {args.host} is not reachable.")

    if args.whois:
        whois_info = whois_lookup(args.host, args.timeout)
        if whois_info:
            print(whois_info)
        else:
            print(f"WHOIS lookup failed for {args.host}.")

    if args.http_get:
        http_content = http_get_request(args.host, args.timeout)
        if http_content:
            print(http_content[:500] + "..." if len(http_content) > 500 else http_content) # Print only the first 500 chars
        else:
            print(f"HTTP GET request failed for {args.host}.")

# Example usage within main()
    if not any([args.ping, args.whois, args.http_get]):
        print("No operation specified.  Use --help for options.")
        logging.info("No operation selected.  Displaying help message.")


if __name__ == "__main__":
    main()