# CDN Edge IP Cleanliness Checker

A lightweight, multi-threaded Python scanner for testing CDN edge IPs
in both **domain fronting** (with custom SNI) and **domainless fronting**
(empty SNI) configurations. It helps you quickly identify which IPs can
be used for TLS-based circumvention or tunneling.

## 
## Quickstart

```bash
# Clone the repository (or download ip_checker.py directly)
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-scanner
```

#### Create a list of IPs (one per line):
```bash
echo "23.209.22.214" > ips.txt
```

#### Run a domainless scan (empty SNI) - most common use case:
```bash
python cdn_ip_checker.py -f ips.txt
```

Clean IPs are saved to clean_domainless.txt and printed on screen

#### Full fronting test with an SNI:
``` bash
python ip_checker.py -f ips.txt --sni speedtest.net
```
Adjust concurrency and timeout as needed:

```bash
python ip_checker.py -f ips.txt -w 50 -t 3
```

## Table of Contents

- [How It Works](#how-it-works)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Domainless scan (empty SNI)](#domainless-scan-empty-sni)
  - [Domain fronting scan (with SNI)](#domain-fronting-scan-with-sni)
- [Output](#output)
- [How the Empty-SNI (Domainless) Handshake Works](#how-the-empty-sni-domainless-handshake-works)
- [Use Cases](#use-cases)

---

## How It Works

The script performs a two?step test for each IP address:

1. **TCP connection** to port 443 - verifies the IP is reachable.
2. **TLS handshake**:
   - **Without an SNI** (domainless mode): the `ClientHello` contains no
     Server Name Indication extension. If the server completes the
     handshake, the IP is considered **clean**.
   - **With an SNI** (fronting mode): the handshake includes the given
     SNI, followed by an HTTP `GET` request with a matching `Host` header.
     Any valid HTTP response (200, 403, 404, etc.) marks the IP as clean.

Tests are executed concurrently using thread pools, allowing hundreds of
IPs to be scanned in seconds.

---

## Features

- **Dual?mode scanning** - run purely domainless tests (empty SNI) or
  combine them with classic domain fronting checks.
- **No external dependencies** - uses only Python?s standard library.
- **Configurable concurrency and timeout** - fine?tune for your network
  conditions.
- **Automatic output files** - clean IPs saved as plain text, ready for
  import into your circumvention tools.

---

## Requirements

- Python **3.6** or newer
- No third?party packages required

Tested on Linux and macOS.

---

## Installation

Clone the repository or download the script directly. No package
installation is needed.

```bash
git clone https://github.com/FarazFe/cdn-ip-checker.git
cd cdn-ip-checker
```

## Usage
Prepare a text file with one IP address per line. Lines starting with #
are treated as comments and ignored.

### Domainless scan (empty SNI)
``` bash
python ip_checker.py -f ips.txt
```
Tests each IP without any SNI. Clean IPs are saved to clean_domainless.txt.

### Domain fronting scan (with SNI)
If you also need IPs that work with a specific SNI (traditional domain
fronting), use the --sni flag. The script then tests both fronting
and domainless modes for every IP:

``` bash
python ip_checker.py -f ips.txt --sni a248.e.akamai.net
```
Results are split into clean_fronting.txt and clean_domainless.txt.

Advanced options
``` text
-f, --file       Path to IP list file (required)
--sni            SNI hostname (omit for domainless only)
-t, --timeout    Per?test timeout in seconds (default: 5)
-w, --workers    Number of parallel threads (default: 20)
```
Example with custom timeout and more workers:

``` bash
python ip_checker.py -f akamai_ips.txt --sni example.com -t 3 -w 50
```
## Output
During the scan, each IP is printed with a ? or ? along with a status
message:

``` text
? 23.209.22.214   -> clean (TLS handshake OK)
? 1.2.3.4         -> failed (TCP connect failed)
```
After completion, a summary is displayed and the clean IPs are written
to text files:

clean_domainless.txt (domainless mode)
clean_fronting.txt & clean_domainless.txt (when --sni is provided)

These lists can be directly imported into your client applications.

## How the Empty-SNI (Domainless) Handshake Works
Certain CDN edge servers are configured to accept TLS connections even
when the client does not include a Server Name Indication (SNI) in
the ClientHello. Instead of rejecting the connection, the server
responds with a generic or default certificate.

Empty SNI - the server_name extension is omitted entirely.

No certificate verification - the client accepts the certificate
without checking hostname validity (common in circumvention tools).

Direct protocol - after the TLS tunnel is established, the
application can run its own protocol (e.g., obfuscated SSH, custom
proxy) without sending an HTTP request.

This method is often called ?domainless fronting? and can bypass network
filters that inspect the SNI field, because the initial handshake reveals
no target domain.

## Use Cases
Pre-filtering IP lists for censorship circumvention tools that support
domainless fronting or empty SNI configurations.

Identifying CDN edge nodes that can act as relay points when SNI?based
blocking is active.

Bulk testing of large IP ranges to find working endpoints before
integrating them into production configurations.
