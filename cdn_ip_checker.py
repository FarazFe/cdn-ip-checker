#!/usr/bin/env python3
"""
CDN IP Checker

Goal:
    Find CDN edge IP candidates that may work with Shirokhorshid-style usage.

Modes:
    fast:
        Fast compatibility scan.

        Without --sni:
            profile = empty-sni
            Tests:
                - TCP connect
                - Python/OpenSSL TLS with no SNI

        With --sni:
            profile = sni-fronting
            Tests:
                - TCP connect
                - Python/OpenSSL TLS with SNI
                - HTTP/1.1 request with Host header

    full:
        Reserved for future real tunnel verification.
        For now, it runs FAST checks and marks mode=full.

Outputs:
    results.txt
    results.jsonl
"""

from __future__ import annotations

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
DEFAULT_ATTEMPTS = 1


# ============================================================
# Result models
# ============================================================

@dataclass
class ProbeResult:
    name: str
    success: int
    attempts: int
    last_error: str = ""

    @property
    def ok(self) -> bool:
        return self.success > 0

    def ratio(self) -> str:
        return f"{self.success}/{self.attempts}"


@dataclass
class ScanResult:
    ip: str
    mode: str
    profile: str
    sni: str
    tcp_ok: bool
    tcp: str
    tls_openssl: str
    http_fronting: str
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
            f"tcp={self.tcp}",
            f"tls_openssl={self.tls_openssl}",
            f"http_fronting={self.http_fronting}",
            f"tls_go={self.tls_go}",
            f"tls_utls_chrome={self.tls_utls_chrome}",
            f"score={self.score_passed}/{self.score_total}",
            f"status={self.status}",
        ])

        if self.error:
            parts.append(f"error={self.error}")

        return " ".join(parts)


# ============================================================
# Input handling
# ============================================================

def load_ips(path: str) -> list[str]:
    ip_file = Path(path)

    if not ip_file.exists():
        print(f"[!] IP file not found: {path}")
        sys.exit(1)

    ips: list[str] = []

    with ip_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            ips.append(line)

    return ips


# ============================================================
# Low-level network functions
# ============================================================

def tcp_connect(ip: str, timeout: int, port: int = DEFAULT_PORT) -> socket.socket | None:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        return sock
    except Exception:
        return None


def tls_handshake(
        sock: socket.socket,
        server_hostname: str | None,
        timeout: int,
) -> tuple[ssl.SSLSocket | None, dict]:
    """
    Run Python/OpenSSL TLS handshake.

    Important:
        - Certificate verification is disabled.
        - Hostname checking is disabled.
        - TLS is currently forced to TLS 1.2 to preserve the current project behavior.
        - server_hostname=None means empty-SNI behavior.
    """

    info = {
        "tls_version": None,
        "cipher": None,
        "alpn": None,
        "error_type": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()

        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Preserve current scanner behavior.
        # Later we can make this configurable:
        #   --tls-version auto
        #   --tls-version 1.2
        #   --tls-version 1.3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2

        # Do not advertise ALPN yet.
        # We are intentionally keeping the Python probe simple.
        # Later Go/uTLS probes can test more realistic ClientHello fingerprints.
        # context.set_alpn_protocols(["http/1.1"])

        sock.settimeout(timeout)

        tls_sock = context.wrap_socket(
            sock,
            server_hostname=server_hostname,
        )

        info["tls_version"] = tls_sock.version()
        info["cipher"] = tls_sock.cipher()
        info["alpn"] = tls_sock.selected_alpn_protocol()

        return tls_sock, info

    except Exception as e:
        info["error_type"] = type(e).__name__
        info["error"] = str(e)

        try:
            sock.close()
        except Exception:
            pass

        return None, info


# ============================================================
# Probe helpers
# ============================================================

def probe_tcp(ip: str, timeout: int, attempts: int) -> ProbeResult:
    success = 0
    last_error = ""

    for _ in range(attempts):
        sock = tcp_connect(ip, timeout)

        if sock:
            success += 1
            try:
                sock.close()
            except Exception:
                pass
        else:
            last_error = "TCP failed"

    return ProbeResult(
        name="tcp",
        success=success,
        attempts=attempts,
        last_error=last_error,
    )


def probe_tls_openssl(
        ip: str,
        timeout: int,
        attempts: int,
        sni: str | None = None,
) -> ProbeResult:
    success = 0
    last_error = ""

    for _ in range(attempts):
        sock = tcp_connect(ip, timeout)

        if not sock:
            last_error = "TCP failed before TLS"
            continue

        tls_sock, info = tls_handshake(sock, sni, timeout)

        if tls_sock:
            success += 1
            try:
                tls_sock.close()
            except Exception:
                pass
        else:
            error_type = info.get("error_type", "unknown")
            error = info.get("error", "unknown")
            last_error = f"{error_type}: {error}"

    return ProbeResult(
        name="tls_openssl",
        success=success,
        attempts=attempts,
        last_error=last_error,
    )


def probe_http_fronting(
        ip: str,
        timeout: int,
        attempts: int,
        sni: str,
) -> ProbeResult:
    success = 0
    last_error = ""

    for _ in range(attempts):
        sock = tcp_connect(ip, timeout)

        if not sock:
            last_error = "TCP failed before HTTP fronting"
            continue

        tls_sock, info = tls_handshake(sock, sni, timeout)

        if not tls_sock:
            error_type = info.get("error_type", "unknown")
            error = info.get("error", "unknown")
            last_error = f"TLS failed before HTTP fronting: {error_type}: {error}"
            continue

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()

        try:
            tls_sock.settimeout(timeout)
            tls_sock.sendall(request)

            response = tls_sock.recv(1024).decode(errors="ignore")

            if response.strip().startswith("HTTP/"):
                success += 1
            else:
                last_error = "Response did not start with HTTP/"

        except Exception as e:
            last_error = f"{type(e).__name__}: {repr(e)}"

        finally:
            try:
                tls_sock.close()
            except Exception:
                pass

    return ProbeResult(
        name="http_fronting",
        success=success,
        attempts=attempts,
        last_error=last_error,
    )


def skipped_probe(name: str) -> ProbeResult:
    return ProbeResult(
        name=name,
        success=0,
        attempts=0,
        last_error="skipped",
    )


# ============================================================
# Policy helpers
# ============================================================

def probe_value(probe: ProbeResult) -> str:
    if probe.attempts == 0:
        return "skipped"

    return probe.ratio()


def status_from_score(tcp_ok: bool, score_passed: int) -> str:
    if not tcp_ok:
        return "bad"

    if score_passed == 0:
        return "maybe"

    if score_passed == 1:
        return "candidate"

    return "strong"


# ============================================================
# FAST profile implementations
# ============================================================

def test_fast_empty_sni(
        ip: str,
        timeout: int,
        attempts: int,
        mode: str = "fast",
) -> ScanResult:
    """
    FAST empty-SNI profile.

    Meaning:
        User did not provide --sni.

    Tests:
        - TCP
        - Python/OpenSSL TLS with server_hostname=None

    Policy:
        TCP failed              => bad
        TCP ok, TLS failed      => maybe
        TCP ok, TLS succeeded   => candidate

    Later:
        Go/uTLS probes can raise candidate to strong.
    """

    tcp = probe_tcp(ip, timeout, attempts)

    if not tcp.ok:
        return ScanResult(
            ip=ip,
            mode=mode,
            profile="empty-sni",
            sni="",
            tcp_ok=False,
            tcp=probe_value(tcp),
            tls_openssl="skipped",
            http_fronting="skipped",
            tls_go="skipped",
            tls_utls_chrome="skipped",
            score_passed=0,
            score_total=1,
            status="bad",
            error=tcp.last_error,
        )

    tls_openssl = probe_tls_openssl(
        ip=ip,
        timeout=timeout,
        attempts=attempts,
        sni=None,
    )

    score_passed = 1 if tls_openssl.ok else 0
    score_total = 1

    return ScanResult(
        ip=ip,
        mode=mode,
        profile="empty-sni",
        sni="",
        tcp_ok=True,
        tcp=probe_value(tcp),
        tls_openssl=probe_value(tls_openssl),
        http_fronting="skipped",
        tls_go="skipped",
        tls_utls_chrome="skipped",
        score_passed=score_passed,
        score_total=score_total,
        status=status_from_score(True, score_passed),
        error="" if tls_openssl.ok else tls_openssl.last_error,
    )


def test_fast_sni_fronting(
        ip: str,
        sni: str,
        timeout: int,
        attempts: int,
        mode: str = "fast",
) -> ScanResult:
    """
    FAST SNI/fronting profile.

    Meaning:
        User provided --sni.

    Tests:
        - TCP
        - Python/OpenSSL TLS with server_hostname=sni
        - HTTP/1.1 GET / with Host: sni

    Policy:
        TCP failed                    => bad
        TCP ok, TLS failed            => maybe
        TCP ok, TLS ok, HTTP failed   => candidate
        TCP ok, TLS ok, HTTP ok       => strong
    """

    tcp = probe_tcp(ip, timeout, attempts)

    if not tcp.ok:
        return ScanResult(
            ip=ip,
            mode=mode,
            profile="sni-fronting",
            sni=sni,
            tcp_ok=False,
            tcp=probe_value(tcp),
            tls_openssl="skipped",
            http_fronting="skipped",
            tls_go="skipped",
            tls_utls_chrome="skipped",
            score_passed=0,
            score_total=2,
            status="bad",
            error=tcp.last_error,
        )

    tls_openssl = probe_tls_openssl(
        ip=ip,
        timeout=timeout,
        attempts=attempts,
        sni=sni,
    )

    http_fronting = probe_http_fronting(
        ip=ip,
        timeout=timeout,
        attempts=attempts,
        sni=sni,
    )

    score_passed = 0

    if tls_openssl.ok:
        score_passed += 1

    if http_fronting.ok:
        score_passed += 1

    score_total = 2

    error = ""

    if not tls_openssl.ok:
        error = tls_openssl.last_error
    elif not http_fronting.ok:
        error = http_fronting.last_error

    return ScanResult(
        ip=ip,
        mode=mode,
        profile="sni-fronting",
        sni=sni,
        tcp_ok=True,
        tcp=probe_value(tcp),
        tls_openssl=probe_value(tls_openssl),
        http_fronting=probe_value(http_fronting),
        tls_go="skipped",
        tls_utls_chrome="skipped",
        score_passed=score_passed,
        score_total=score_total,
        status=status_from_score(True, score_passed),
        error=error,
    )


def test_fast(
        ip: str,
        timeout: int,
        attempts: int,
        sni: str | None = None,
        mode: str = "fast",
) -> ScanResult:
    if sni:
        return test_fast_sni_fronting(
            ip=ip,
            sni=sni,
            timeout=timeout,
            attempts=attempts,
            mode=mode,
        )

    return test_fast_empty_sni(
        ip=ip,
        timeout=timeout,
        attempts=attempts,
        mode=mode,
    )


# ============================================================
# Output helpers
# ============================================================

def save_results(results: list[ScanResult]) -> None:
    with open("results.txt", "w", encoding="utf-8") as f:
        for result in results:
            f.write(result.to_text_line() + "\n")

    with open("results.jsonl", "w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(asdict(result), ensure_ascii=False) + "\n")

    usable_results = [
        result
        for result in results
        if result.status in {"strong", "candidate", "maybe"}
    ]

    status_rank = {
        "strong": 0,
        "candidate": 1,
        "maybe": 2,
        "bad": 3,
    }

    usable_results.sort(
        key=lambda result: (
            status_rank.get(result.status, 99),
            result.ip,
        )
    )

    with open("candidate_ips.txt", "w", encoding="utf-8") as f:
        for result in usable_results:
            f.write(result.ip + "\n")

    print(f"[*] Saved {len(results)} detailed results to results.txt")
    print(f"[*] Saved {len(results)} machine-readable results to results.jsonl")
    print(f"[*] Saved {len(usable_results)} candidate IPs to candidate_ips.txt")


def status_icon(status: str) -> str:
    if status == "bad":
        return "❌"

    if status == "maybe":
        return "⚠️"

    if status == "candidate":
        return "✅"

    if status == "strong":
        return "🔥"

    if status == "confirmed":
        return "🏆"

    return "•"


# ============================================================
# CLI
# ============================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CDN edge IP checker for Shirokhorshid-style compatibility testing."
    )

    parser.add_argument(
        "-f",
        "--file",
        default="ips.txt",
        help="Input file containing IPs, one per line. Default: ips.txt",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Number of concurrent workers. Default: {DEFAULT_WORKERS}",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout in seconds. Default: {DEFAULT_TIMEOUT}",
    )

    parser.add_argument(
        "--attempts",
        type=int,
        default=DEFAULT_ATTEMPTS,
        help=f"Number of attempts per probe. Default: {DEFAULT_ATTEMPTS}",
    )

    parser.add_argument(
        "--mode",
        choices=["fast", "full"],
        default="fast",
        help="Scan mode: fast or full. FULL is a placeholder for future tunnel verification.",
    )

    parser.add_argument(
        "--sni",
        default=None,
        help="Optional SNI hostname. If provided, scanner uses the sni-fronting profile.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.workers < 1:
        print("[!] --workers must be at least 1")
        sys.exit(1)

    if args.timeout < 1:
        print("[!] --timeout must be at least 1 second")
        sys.exit(1)

    if args.attempts < 1:
        print("[!] --attempts must be at least 1")
        sys.exit(1)

    ips = load_ips(args.file)

    if not ips:
        print("[!] No IPs found in input file.")
        sys.exit(1)

    profile = "sni-fronting" if args.sni else "empty-sni"

    print(f"[*] Loaded {len(ips)} IPs from {args.file}")
    print(f"[*] Mode: {args.mode}")
    print(f"[*] Profile: {profile}")
    print(f"[*] Workers: {args.workers}")
    print(f"[*] Timeout: {args.timeout}s")
    print(f"[*] Attempts: {args.attempts}")

    if args.sni:
        print(f"[*] SNI: {args.sni}")

    if args.mode == "full":
        print("[!] FULL mode tunnel verification is not implemented yet.")
        print("[!] Running FAST checks only and marking mode=full.")

    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_ip = {
            executor.submit(
                test_fast,
                ip,
                args.timeout,
                args.attempts,
                args.sni,
                args.mode,
            ): ip
            for ip in ips
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                result = future.result()
                results.append(result)

                print(f"{status_icon(result.status)} {result.to_text_line()}")

            except Exception as e:
                print(f"❌ {ip} error={type(e).__name__}: {repr(e)}")

    results.sort(key=lambda r: r.ip)
    save_results(results)


if __name__ == "__main__":
    main()
