#!/usr/bin/env python3
"""Classify CIDR ranges by city using the IPinfo API."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


IPINFO_LOOKUP_URL = "https://api.ipinfo.io/lookup/"
REQUEST_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 3
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WHITESPACE = re.compile(r'\s+')


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify IPv4 and IPv6 CIDRs into city-specific text files."
    )
    parser.add_argument("--input", required=True, type=Path, help="Input CIDR list")
    parser.add_argument("--token", required=True, help="IPinfo API token")
    parser.add_argument("--output-dir", required=True, type=Path, help="Output directory")
    return parser.parse_args()


def city_name(response: dict[str, object]) -> str | None:
    geo = response.get("geo")
    if isinstance(geo, dict):
        city = geo.get("city")
        if isinstance(city, str) and city.strip():
            return city.strip()

    city = response.get("city")
    return city.strip() if isinstance(city, str) and city.strip() else None


def lookup_city(address: ipaddress.IPv4Address | ipaddress.IPv6Address, token: str) -> str | None:
    request = Request(
        f"{IPINFO_LOOKUP_URL}{quote(str(address), safe='')}",
        headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
    )

    for attempt in range(MAX_ATTEMPTS):
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = json.load(response)
            if not isinstance(payload, dict):
                raise RuntimeError("IPinfo returned a non-object JSON response")
            return city_name(payload)
        except HTTPError as error:
            if error.code in (400, 401, 403, 404):
                raise RuntimeError(f"IPinfo lookup failed for {address}: HTTP {error.code}") from error
            if error.code != 429 and not 500 <= error.code < 600:
                raise RuntimeError(f"IPinfo lookup failed for {address}: HTTP {error.code}") from error
        except (URLError, TimeoutError) as error:
            if attempt == MAX_ATTEMPTS - 1:
                raise RuntimeError(f"IPinfo lookup failed for {address}: {error}") from error

        if attempt == MAX_ATTEMPTS - 1:
            raise RuntimeError(f"IPinfo lookup failed for {address} after {MAX_ATTEMPTS} attempts")
        time.sleep(2**attempt)

    raise AssertionError("unreachable")


def file_stem(location: str) -> str:
    sanitized = INVALID_FILENAME_CHARS.sub("_", location).strip(". ")
    sanitized = WHITESPACE.sub("_", sanitized)
    return sanitized or "Unknown"


def read_networks(input_path: Path) -> Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    with input_path.open(encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            try:
                yield ipaddress.ip_network(value, strict=False)
            except ValueError:
                print(f"Skipping invalid CIDR at line {line_number}: {value}", file=sys.stderr)


def classify(
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network], token: str
) -> tuple[DefaultDict[str, set[str]], DefaultDict[str, set[str]]]:
    ipv4_by_city: DefaultDict[str, set[str]] = defaultdict(set)
    ipv6_by_city: DefaultDict[str, set[str]] = defaultdict(set)

    skipped_ipv4 = 0
    skipped_ipv6 = 0

    for network in networks:
        location = lookup_city(network.network_address, token)
        if location is None:
            if network.version == 4:
                skipped_ipv4 += 1
            else:
                skipped_ipv6 += 1
            continue

        target = ipv4_by_city if network.version == 4 else ipv6_by_city
        target[location].add(str(network))

    print(
        f"Skipped {skipped_ipv4} IPv4 and {skipped_ipv6} IPv6 ranges without city-level data.",
        file=sys.stderr,
    )
    return ipv4_by_city, ipv6_by_city


def network_sort_key(value: str) -> tuple[int, int, int]:
    network = ipaddress.ip_network(value)
    return network.version, int(network.network_address), network.prefixlen


def write_list(path: Path, networks: set[str]) -> None:
    path.write_text("\n".join(sorted(networks, key=network_sort_key)) + "\n", encoding="utf-8")


def write_output(
    output_dir: Path,
    ipv4_by_city: DefaultDict[str, set[str]],
    ipv6_by_city: DefaultDict[str, set[str]],
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.glob("*-4.txt"):
        path.unlink()
    for path in output_dir.glob("*-6.txt"):
        path.unlink()
    for path in output_dir.glob("*-46.txt"):
        path.unlink()

    for location in sorted(set(ipv4_by_city) | set(ipv6_by_city)):
        stem = file_stem(location)
        ipv4 = ipv4_by_city[location]
        ipv6 = ipv6_by_city[location]
        write_list(output_dir / f"{stem}-4.txt", ipv4)
        write_list(output_dir / f"{stem}-6.txt", ipv6)
        write_list(output_dir / f"{stem}-46.txt", ipv4 | ipv6)


def main() -> int:
    args = parse_arguments()
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1
    if not args.token:
        print("IPinfo API token must not be empty.", file=sys.stderr)
        return 1

    ipv4_by_city, ipv6_by_city = classify(read_networks(args.input), args.token)
    write_output(args.output_dir, ipv4_by_city, ipv6_by_city)
    print(f"Wrote {len(set(ipv4_by_city) | set(ipv6_by_city))} location groups.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
