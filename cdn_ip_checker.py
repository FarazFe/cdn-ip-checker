#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 10
DEFAULT_PORT = 443
DEFAULT_WORKERS = 10
DEFAULT_ATTEMPTS = 3


# ----------------------------------------------------------------------
# Result model
# ----------------------------------------------------------------------

@dataclass
class ScanResult:
    ip: str
    mode: str
    profile: str
    sni: str

    tcp_ok: bool
    tcp_success: int
    tcp_attempts: int

    tls_openssl: str
    tls_openssl_success: int
    tls_openssl_attempts: int

    http_fronting: str
    http_fronting_success: int
    http_fronting_attempts: int

    tls_go: str
    tls_utls_chrome: str

    score_passed: int
    score_total: int
    status: str
    error: str = ""

    def to_text_line(self) -> str:
        parts = [
            self.ip,
            f"mode={self.mode}",
            f"profile={self.profile}",
        ]

        if self.sni:
            parts.append(f"sni={self.sni}")

        parts.extend([
            f"tcp_ok={str(self.tcp_ok).lower()}",
            f"tcp={self.tcp_success}/{self.tcp_attempts}",
            f"tls_openssl={self.tls_openssl}",
            f"http_fronting={self.http_fronting}",
            f"tls_go={self.tls_go}",
            f"tls_utls_chrome={self.tls_utls_chrome}",
            f"score={self.score_passed}/{self.score_total}",
            f"status={self.status}",
        ])

        if self.error:
            parts.append(f"error={self.error}")

        return "  ".join(parts)


# ----------------------------------------------------------------------
# Low-level test helpers
# ----------------------------------------------------------------------

def tcp_connect(ip: str, timeout: int) -> socket.socket | None:
    try:
        return socket.create_connection((ip, DEFAULT_PORT), timeout=timeout)
    except (socket.timeout, OSError):
        return None


def tls_handshake(sock: socket.socket, sni: str | None, timeout: int):
    """
    Perform a Python/OpenSSL TLS handshake over an already-connected TCP socket.

    For now we keep the TLS profile intentionally simple and close to your current
    debugging setup:
      - certificate verification disabled
      - hostname verification disabled
      - TLS 1.2 forced
      - no ALPN advertised

    Later we can make TLS version and ALPN configurable.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    # context.set_alpn_protocols(["http/1.1"])

    try:
        sock.settimeout(timeout)
        tls_sock = context.wrap_socket(sock, server_hostname=sni)

        info = {
            "ok": True,
            "sni": sni,
            "alpn": tls_sock.selected_alpn_protocol(),
            "version": tls_sock.version(),
            "cipher": tls_sock.cipher(),
            "error_type": None,
            "error": None,
        }
        return tls_sock, info

    except Exception as e:
        info = {
            "ok": False,
            "sni": sni,
            "alpn": None,
            "version": None,
            "cipher": None,
            "error_type": type(e).__name__,
            "error": repr(e),
        }
        return None, info


# ----------------------------------------------------------------------
# Shared scoring / formatting helpers
# ----------------------------------------------------------------------

def bool_count_string(success: int, attempts: int) -> str:
    if attempts == 0:
        return "skipped"

    return f"{success}/{attempts}"


def format_probe_error(prefix: str, info: dict) -> str:
    error_type = info.get("error_type")
    error = info.get("error")

    if not error_type and not error:
        return ""

    return f"{prefix}: {error_type}: {error}"


def close_socket_quietly(sock) -> None:
    try:
        if sock:
            sock.close()
    except Exception:
        pass


def status_for_empty_sni(
    tcp_success: int,
    tcp_attempts: int,
    tls_success: int,
    tls_attempts: int,
) -> str:
    if tcp_success == 0:
        return "bad"

    if tls_success == 0:
        return "maybe"

    if tcp_success == tcp_attempts and tls_attempts > 0 and tls_success == tls_attempts:
        return "strong"

    return "candidate"


def status_for_sni_fronting(
    tcp_success: int,
    tcp_attempts: int,
    tls_success: int,
    tls_attempts: int,
    http_success: int,
    http_attempts: int,
) -> str:
    if tcp_success == 0:
        return "bad"

    if tls_success == 0:
        return "maybe"

    if http_success == 0:
        return "candidate"

    if (
        tcp_success == tcp_attempts
        and tls_attempts > 0
        and tls_success == tls_attempts
        and http_attempts > 0
        and http_success == http_attempts
    ):
        return "strong"

    return "candidate"


# ----------------------------------------------------------------------
# FAST mode profiles
# ----------------------------------------------------------------------

def test_fast_empty_sni(ip: str, timeout: int, attempts: int) -> ScanResult:
    """
    FAST profile: empty-sni

    This is used when the user does NOT provide --sni.
    It matches the Shirokhorshid setup where users only enter CDN edge IPs.
    """
    tcp_success = 0
    tls_success = 0
    tls_attempts = 0
    last_error = ""

    for _ in range(attempts):
        sock = tcp_connect(ip, timeout)

        if not sock:
            last_error = "TCP failed"
            continue

        tcp_success += 1
        tls_attempts += 1
        tls_sock, info = tls_handshake(sock, None, timeout)

        if tls_sock:
            tls_success += 1
            close_socket_quietly(tls_sock)
            continue

        close_socket_quietly(sock)
        last_error = format_probe_error("TLS empty-SNI failed", info)

    score_passed = 1 if tls_success > 0 else 0
    score_total = 1
    tcp_ok = tcp_success > 0

    return ScanResult(
        ip=ip,
        mode="fast",
        profile="empty-sni",
        sni="",
        tcp_ok=tcp_ok,
        tcp_success=tcp_success,
        tcp_attempts=attempts,
        tls_openssl=bool_count_string(tls_success, tls_attempts),
        tls_openssl_success=tls_success,
        tls_openssl_attempts=tls_attempts,
        http_fronting="skipped",
        http_fronting_success=0,
        http_fronting_attempts=0,
        tls_go="skipped",
        tls_utls_chrome="skipped",
        score_passed=score_passed,
        score_total=score_total,
        status=status_for_empty_sni(tcp_success, attempts, tls_success, tls_attempts),
        error="" if tls_success > 0 else last_error,
    )


def test_fast_sni_fronting(ip: str, sni: str, timeout: int, attempts: int) -> ScanResult:
    """
    FAST profile: sni-fronting

    This is used when the user provides --sni.
    It tests TLS with that SNI and then sends a basic HTTP/1.1 request with Host: sni.
    """
    tcp_success = 0
    tls_success = 0
    tls_attempts = 0
    http_success = 0
    http_attempts = 0
    last_error = ""

    for _ in range(attempts):
        sock = tcp_connect(ip, timeout)

        if not sock:
            last_error = "TCP failed"
            continue

        tcp_success += 1
        tls_attempts += 1
        tls_sock, info = tls_handshake(sock, sni, timeout)

        if not tls_sock:
            close_socket_quietly(sock)
            last_error = format_probe_error(f"TLS with SNI {sni} failed", info)
            continue

        tls_success += 1
        http_attempts += 1

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
                http_success += 1
            else:
                last_error = "TLS succeeded, but response did not start with HTTP/"

        except Exception as e:
            last_error = f"HTTP fronting failed: {type(e).__name__}: {repr(e)}"

        finally:
            close_socket_quietly(tls_sock)

    score_passed = 0
    if tls_success > 0:
        score_passed += 1
    if http_success > 0:
        score_passed += 1

    score_total = 2
    tcp_ok = tcp_success > 0

    return ScanResult(
        ip=ip,
        mode="fast",
        profile="sni-fronting",
        sni=sni,
        tcp_ok=tcp_ok,
        tcp_success=tcp_success,
        tcp_attempts=attempts,
        tls_openssl=bool_count_string(tls_success, tls_attempts),
        tls_openssl_success=tls_success,
        tls_openssl_attempts=tls_attempts,
        http_fronting=bool_count_string(http_success, http_attempts),
        http_fronting_success=http_success,
        http_fronting_attempts=http_attempts,
        tls_go="skipped",
        tls_utls_chrome="skipped",
        score_passed=score_passed,
        score_total=score_total,
        status=status_for_sni_fronting(
            tcp_success,
            attempts,
            tls_success,
            tls_attempts,
            http_success,
            http_attempts,
        ),
        error="" if http_success > 0 else last_error,
    )


def test_fast(ip: str, timeout: int, attempts: int, sni: str | None = None) -> ScanResult:
    if sni:
        return test_fast_sni_fronting(ip, sni, timeout, attempts)

    return test_fast_empty_sni(ip, timeout, attempts)


# ----------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------

def save_results(results: list[ScanResult]) -> None:
    with open("results.txt", "w") as f:
        for result in results:
            f.write(result.to_text_line() + "\n")

    with open("results.jsonl", "w") as f:
        for result in results:
            f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")

    print(f"[*] Saved {len(results)} results to results.txt")
    print(f"[*] Saved {len(results)} results to results.jsonl")


def print_result(result: ScanResult) -> None:
    if result.status == "bad":
        icon = "❌"
    elif result.status == "maybe":
        icon = "⚠️"
    elif result.status == "candidate":
        icon = "🟡"
    else:
        icon = "✅"

    print(f"{icon} {result.to_text_line()}")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Shirokhorshid CDN Edge IP Checker")
    parser.add_argument("-f", "--file", required=True, help="File with IPs")
    parser.add_argument("--sni", default=None, help="SNI hostname; enables sni-fronting profile")
    parser.add_argument("--mode", choices=["fast", "full"], default="fast", help="Scan mode: fast or full")
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS, help="Attempts per IP")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS)
    args = parser.parse_args()

    if args.attempts < 1:
        print("Error: --attempts must be at least 1")
        sys.exit(1)

    ip_path = Path(args.file)
    if not ip_path.is_file():
        print(f"Error: {args.file} not found")
        sys.exit(1)

    with open(ip_path, "r") as f:
        ips = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not ips:
        print("No IPs to test.")
        sys.exit(0)

    print(
        f"[*] Testing {len(ips)} IPs with "
        f"{args.workers} workers and {args.attempts} attempts per IP..."
    )

    if args.mode == "full":
        print("[!] FULL mode tunnel verification is not implemented yet.")
        print("[!] Running FAST checks only for now.")

    if args.sni:
        print(f"[*] FAST profile: sni-fronting | sni={args.sni}")
    else:
        print("[*] FAST profile: empty-sni")

    scan_results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {
            executor.submit(test_fast, ip, args.timeout, args.attempts, args.sni): ip
            for ip in ips
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                result = future.result()
                scan_results.append(result)
                print_result(result)
            except Exception as e:
                print(f"❌ {ip} error={type(e).__name__}: {repr(e)}")

    save_results(scan_results)


if __name__ == "__main__":
    main()