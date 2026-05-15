#!/usr/bin/env python3
import socket
import ssl
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_TIMEOUT = 5
DEFAULT_PORT = 443
DEFAULT_WORKERS = 10
RETRIES = 3


# ----------------------------------------------------------------------
# Low-level test helpers
# ----------------------------------------------------------------------

def tcp_connect(ip: str, timeout: int) -> socket.socket | None:
    try:
        sock = socket.create_connection((ip, DEFAULT_PORT), timeout=timeout)
        return sock
    except (socket.timeout, OSError):
        return None


def tls_handshake(sock: socket.socket, sni: str | None, timeout: int):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(['http/1.1'])

    try:
        sock.settimeout(timeout)
        tls_sock = context.wrap_socket(sock, server_hostname=sni)
        negotiated = tls_sock.selected_alpn_protocol()
        return tls_sock, negotiated
    except (ssl.SSLError, socket.timeout, OSError):
        return None, None


# ----------------------------------------------------------------------
# Mode tests
# ----------------------------------------------------------------------

def test_domainless(ip: str, timeout: int) -> dict:
    result = {"ip": ip, "mode": "domainless", "status": "failed", "message": ""}
    for _ in range(RETRIES):
        sock = tcp_connect(ip, timeout)
        if not sock:
            result["message"] = "TCP failed"
            continue

        tls_sock, alpn = tls_handshake(sock, None, timeout)
        if tls_sock:
            tls_sock.close()
            result["status"] = "clean"
            result["message"] = f"TLS OK (ALPN: {alpn})"
            return result
        else:
            result["message"] = "TLS failed"
            if sock: sock.close()
    return result


def test_fronting(ip: str, sni: str, timeout: int) -> dict:
    result = {"ip": ip, "mode": "fronting", "status": "failed", "message": ""}
    for _ in range(RETRIES):
        sock = tcp_connect(ip, timeout)
        if not sock:
            result["message"] = "TCP failed"
            continue

        tls_sock, alpn = tls_handshake(sock, sni, timeout)
        if not tls_sock:
            result["message"] = "TLS failed"
            if sock: sock.close()
            continue

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode()

        try:
            tls_sock.settimeout(timeout)
            tls_sock.sendall(request)
            response = tls_sock.recv(1024).decode(errors="ignore")

            if response.strip().startswith("HTTP/"):
                first_line = response.splitlines()[0]
                result["status"] = "clean"
                result["message"] = f"{first_line} | ALPN: {alpn}"
                return result
            else:
                result["message"] = "No HTTP header"
        except (socket.timeout, OSError):
            result["message"] = "Read error"
        finally:
            if tls_sock: tls_sock.close()

    return result


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Shirokhorshid IP Checker")
    parser.add_argument("-f", "--file", required=True, help="File with IPs")
    parser.add_argument("--sni", default=None, help="SNI hostname")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS)
    args = parser.parse_args()

    ip_path = Path(args.file)
    if not ip_path.is_file():
        print(f"Error: {args.file} not found")
        sys.exit(1)

    with open(ip_path, "r") as f:
        ips = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not ips:
        print("No IPs to test.")
        sys.exit(0)

    print(f"[*] Testing {len(ips)} IPs with {args.workers} workers...")

    results = {"fronting": [], "domainless": []}

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_info = {}

        for ip in ips:
            f_dom = executor.submit(test_domainless, ip, args.timeout)
            future_to_info[f_dom] = (ip, "domainless")

            # Test fronting ONLY if SNI is provided
            if args.sni:
                f_front = executor.submit(test_fronting, ip, args.sni, args.timeout)
                future_to_info[f_front] = (ip, "fronting")

        for future in as_completed(future_to_info):
            ip, mode = future_to_info[future]
            try:
                res = future.result()
                icon = "✅" if res["status"] == "clean" else "❌"
                print(f"{icon} {res['ip']:15s} [{res['mode']:11s}] {res['message']}")

                if res["status"] == "clean":
                    results[mode].append(ip)
            except Exception as e:
                print(f"❌ {ip:15s} [{mode:11s}] Error: {e}")

    for mode, clean_ips in results.items():
        if clean_ips:
            filename = f"clean_{mode}.txt"
            with open(filename, "w") as f:
                f.write("\n".join(sorted(set(clean_ips))))
            print(f"[*] Saved {len(clean_ips)} clean {mode} IPs to {filename}")


if __name__ == "__main__":
    main()