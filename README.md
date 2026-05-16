# CDN Edge IP Checker

🌐 Languages: [English](README.md) | [فارسی](README_fa.md)

A lightweight, multi-threaded Python scanner for testing CDN edge IPs.
It is designed as a **pre-filter** for clients that
use CDN edge IPs with either empty-SNI behavior or SNI/fronting behavior.

The checker currently has two user-facing scan modes:

- **FAST mode**: performs TCP and TLS/HTTP edge checks.
- **FULL mode**: reserved for future real tunnel verification. For now, it
  runs the FAST checks and clearly reports that tunnel verification is not
  implemented yet.

The scanner does **not** claim that a TLS-successful IP is guaranteed to work
inside the final client. It classifies CDN edge IPs as `bad`, `maybe`,
`candidate`, or `strong` based on the checks that were actually performed.

---

## Table of Contents

- [Quickstart](#quickstart)
- [Preparing IPs from CDN CIDR Ranges](#preparing-ips-from-cdn-cidr-ranges)
- [How It Works](#how-it-works)
- [Scan Profiles](#scan-profiles)
  - [Empty-SNI Profile](#empty-sni-profile)
  - [SNI Fronting Profile](#sni-fronting-profile)
- [Status Meaning](#status-meaning)
- [Output](#output)
- [Usage](#usage)
- [Options](#options)
- [Requirements](#requirements)
- [Installation](#installation)
- [Use Cases](#use-cases)
- [Notes and Limitations](#notes-and-limitations)

---

## Quickstart

Clone the repository:

```bash
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-checker
```

Create an IP list manually:

```bash
echo "23.209.22.214" > ips.txt
```

Or generate IPs from CDN CIDR ranges:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast
```

Run the default FAST scan with empty SNI:

```bash
python cdn_ip_checker.py -f ips.txt
```

Run FAST scan with repeated attempts:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 3 -w 10 -t 10
```

Run FAST SNI/fronting scan:

```bash
python cdn_ip_checker.py -f ips.txt --sni example.com --attempts 3
```

Results are saved to:

```text
results.txt
results.jsonl
```

---

## Preparing IPs from CDN CIDR Ranges

Before running the checker, you need a list of actual IP addresses.

Many CDN providers publish or announce their edge IP ranges in **CIDR notation**.
For example:

```text
104.64.0.0/10
23.32.0.0/11
23.192.0.0/11
```

These are ranges, not individual IPs. To scan them, first generate real IP
addresses from those ranges.

Create a file named `akamai_ranges.txt`:

```text
104.64.0.0/10
23.32.0.0/11
23.192.0.0/11
23.0.0.0/12
```

Generate a random sample from each range:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast
```

By default, this saves generated IPs to:

```text
ips.txt
```

You can also choose a different output file:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast -o my_ips.txt
```

Choose how many IPs to sample from each range:

```bash
python generate_ips.py -f akamai_ranges.txt -m fast -s 1000
```

Generate every IP from every CIDR range:

```bash
python generate_ips.py -f akamai_ranges.txt -m full
```

Be careful with `generate_ips.py -m full`. CDN ranges can be very large and may
generate millions of IPs.

Basic workflow:

```text
CDN CIDR ranges -> generate ips.txt -> run cdn_ip_checker.py
```

---

## How It Works

For each IP, the checker first tries to connect to TCP port 443.

TCP is treated as the hard requirement:

```text
TCP failed -> bad
```

If TCP succeeds, the next check depends on whether `--sni` was provided.

Without `--sni`, the checker runs the **empty-SNI profile**.

With `--sni`, the checker runs the **SNI fronting profile**.

The checker can repeat each IP test multiple times using `--attempts`. This is
important because CDN edge behavior can be noisy. A single failed TLS handshake
does not always mean the IP is unusable.

---

## Scan Profiles

### Empty-SNI Profile

Command:

```bash
python cdn_ip_checker.py -f ips.txt --mode fast
```

This profile is used when `--sni` is not provided.

It tests:

1. TCP connection to the IP on port 443.
2. Python/OpenSSL TLS handshake with no SNI.

This matches the case where a user only enters CDN edge IPs and leaves the SNI
field empty in the client.

Example output:

```text
185.200.232.40  mode=fast  profile=empty-sni  tcp_ok=true  tcp=3/3  tls_openssl=0/3  http_fronting=skipped  tls_go=skipped  tls_utls_chrome=skipped  score=0/1  status=maybe
```

This means:

- TCP worked 3 out of 3 times.
- Python/OpenSSL empty-SNI TLS failed 3 out of 3 times.
- The IP is not rejected, because TCP worked.
- The status is `maybe`, not `bad`.

### SNI Fronting Profile

Command:

```bash
python cdn_ip_checker.py -f ips.txt --mode fast --sni example.com
```

This profile is used when `--sni` is provided.

It tests:

1. TCP connection to the IP on port 443.
2. Python/OpenSSL TLS handshake using the provided SNI.
3. HTTP/1.1 request using `Host: <sni>`.

Example request after TLS succeeds:

```http
GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Connection: close
```

Example output:

```text
1.2.3.4  mode=fast  profile=sni-fronting  sni=example.com  tcp_ok=true  tcp=3/3  tls_openssl=3/3  http_fronting=2/3  tls_go=skipped  tls_utls_chrome=skipped  score=2/2  status=candidate
```

This means:

- TCP worked 3 out of 3 times.
- TLS with SNI worked 3 out of 3 times.
- HTTP response worked 2 out of 3 times.
- The IP is useful, but not fully stable, so it is marked `candidate`.

---

## Status Meaning

The checker uses these statuses:

| Status | Meaning |
|---|---|
| `bad` | TCP failed. The IP is not useful for this scan. |
| `maybe` | TCP worked, but the TLS/fronting check did not succeed. Do not treat this as a final rejection for Shirokhorshid-style use cases. |
| `candidate` | At least one higher-level check succeeded, but not all attempts were stable. |
| `strong` | All required checks for the selected profile succeeded across all attempts. |

Important distinction:

```text
TCP failed -> bad
TCP worked but TLS failed -> maybe
```

This is intentional. Python/OpenSSL TLS failure may be caused by TLS fingerprint
differences, network filtering, CDN behavior, or timing issues. It does not always
prove that the IP cannot work in the final client.

---

## Output

The checker writes two output files:

```text
results.txt
results.jsonl
```

`results.txt` is human-readable:

```text
185.200.232.40  mode=fast  profile=empty-sni  tcp_ok=true  tcp=3/3  tls_openssl=0/3  http_fronting=skipped  tls_go=skipped  tls_utls_chrome=skipped  score=0/1  status=maybe  error=TLS empty-SNI failed: ConnectionResetError: ConnectionResetError(104, 'Connection reset by peer')
```

`results.jsonl` is machine-readable, one JSON object per line. It is useful for
future filtering, ranking, or importing into other tools.

The checker no longer writes separate `clean_domainless.txt` or
`clean_fronting.txt` files. A single result file is easier to understand and
keeps all information together.

---

## Usage

Prepare a text file with one IP address per line:

```text
23.209.22.214
1.2.3.4
5.6.7.8
```

Lines starting with `#` are ignored.

### FAST mode, empty SNI

```bash
python cdn_ip_checker.py -f ips.txt --mode fast
```

Since `fast` is the default mode, this is equivalent:

```bash
python cdn_ip_checker.py -f ips.txt
```

### FAST mode, empty SNI, repeated attempts

```bash
python cdn_ip_checker.py -f ips.txt --attempts 5 -w 10 -t 10
```

### FAST mode, SNI/fronting

```bash
python cdn_ip_checker.py -f ips.txt --mode fast --sni example.com
```

### FULL mode

```bash
python cdn_ip_checker.py -f ips.txt --mode full
```

FULL mode is reserved for future real tunnel verification. In the current version,
it prints a warning and runs the FAST checks only.

---

## Options

```text
-f, --file       Path to IP list file. Required.
--mode           Scan mode: fast or full. Default: fast.
--sni            SNI hostname. If provided, enables the sni-fronting profile.
--attempts       Attempts per IP. Default: 3.
-t, --timeout    Per-connection timeout in seconds. Default: 10.
-w, --workers    Number of parallel worker threads. Default: 10.
```

Examples:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 3 -w 10 -t 10
python cdn_ip_checker.py -f ips.txt --sni example.com --attempts 5 -w 5 -t 15
```

For stability testing, use fewer workers and more attempts:

```bash
python cdn_ip_checker.py -f ips.txt --attempts 5 -w 5 -t 15
```

For broader discovery, you can increase workers, but very high concurrency may
create local network noise or false failures.

---

## Requirements

- Python 3.10 or newer is required.
- No third-party Python packages are required.

The script uses Python's standard library only.

---

## Installation

Clone the repository or download the scripts directly:

```bash
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-checker
```

No package installation is required.

---

## Use Cases

- Pre-filtering CDN edge IPs for clients that support empty-SNI behavior.
- Testing CDN edge IPs with a specific SNI/fronting hostname.
- Comparing noisy CDN edge behavior across repeated attempts.
- Building a candidate list before doing slower, future FULL-mode tunnel verification.

---

## Notes and Limitations

FAST mode is a pre-filter. It does not prove that an IP will work in the final
client or tunnel.

Currently implemented FAST checks:

```text
TCP
Python/OpenSSL TLS
Optional HTTP/1.1 fronting request when --sni is provided
```

Planned future checks:

```text
Go TLS helper
uTLS Chrome-like TLS helper
FULL mode real tunnel verification
```

The output already contains these placeholder fields:

```text
tls_go=skipped
tls_utls_chrome=skipped
```

They are included now so the result format can stay stable when those features
are added later.