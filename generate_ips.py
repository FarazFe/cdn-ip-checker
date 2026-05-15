#!/usr/bin/env python3
import argparse
import ipaddress
import random
from pathlib import Path


def generate_full(network):
    for ip in network.hosts():
        yield ip


def generate_sample(network, count):
    if network.num_addresses <= 2:
        return

    max_hosts = network.num_addresses - 2
    count = min(count, max_hosts)

    used_offsets = set()

    while len(used_offsets) < count:
        offset = random.randint(1, network.num_addresses - 2)
        if offset in used_offsets:
            continue

        used_offsets.add(offset)
        yield network.network_address + offset


def main():
    parser = argparse.ArgumentParser(
        description="Generate IPs from CIDR ranges in full or fast sample mode."
    )

    parser.add_argument(
        "-f",
        "--file",
        default="akamai_ranges.txt",
        help="Input file containing CIDR ranges, one per line. Default: akamai_ranges.txt",
    )

    parser.add_argument(
        "-m",
        "--mode",
        choices=["fast", "full"],
        default="fast",
        help="Generation mode: fast = sample IPs, full = generate all IPs. Default: fast",
    )

    parser.add_argument(
        "-s",
        "--sample-size",
        type=int,
        default=100,
        help="Number of random IPs to generate per range in fast mode. Default: 100",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="ips.txt",
        help="Output file. Default: ips.txt",
    )

    args = parser.parse_args()

    input_path = Path(args.file)
    output_path = Path(args.output)

    if not input_path.is_file():
        raise SystemExit(f"Error: input file not found: {input_path}")

    total_written = 0

    with input_path.open("r") as infile, output_path.open("w") as outfile:
        for line in infile:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            network = ipaddress.ip_network(line, strict=False)

            if args.mode == "full":
                ips = generate_full(network)
            else:
                ips = generate_sample(network, args.sample_size)

            for ip in ips:
                outfile.write(f"{ip}\n")
                total_written += 1

    print(f"Saved {total_written} IPs to {output_path}")


if __name__ == "__main__":
    main()