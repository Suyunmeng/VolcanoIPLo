#!/usr/bin/env python3
"""Classify CIDR ranges by mainland city using the IPinfo API."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import DefaultDict, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


IPINFO_LOOKUP_URL = "https://ipinfo.io/"
REQUEST_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 3
LOOKUP_WORKERS = 8
IPV4_LOOKUP_PREFIX = 24
IPV6_LOOKUP_PREFIX = 48
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
    country = response.get("country")
    if country != "CN":
        return None

    geo = response.get("geo")
    if isinstance(geo, dict):
        city = geo.get("city")
        if isinstance(city, str) and city.strip():
            return city.strip()

    city = response.get("city")
    if isinstance(city, str) and city.strip():
        return city.strip()
    return None


def lookup_city(address: ipaddress.IPv4Address | ipaddress.IPv6Address, token: str) -> str | None:
    request = Request(
        f"{IPINFO_LOOKUP_URL}{quote(str(address), safe='')}/json",
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
            if error.code in (400, 404):
                return None
            if error.code in (401, 403):
                raise RuntimeError(
                    "IPinfo rejected the API token. Verify the IPINFO_TOKEN repository secret."
                ) from error
            if error.code != 429 and not 500 <= error.code < 600:
                raise RuntimeError(f"IPinfo lookup failed for {address}: HTTP {error.code}") from error
        except (URLError, TimeoutError) as error:
            if attempt == MAX_ATTEMPTS - 1:
                raise RuntimeError(f"IPinfo lookup failed for {address}: {error}") from error

        if attempt == MAX_ATTEMPTS - 1:
            raise RuntimeError(f"IPinfo lookup failed for {address} after {MAX_ATTEMPTS} attempts")
        time.sleep(2**attempt)

    raise AssertionError("unreachable")


def sampled_address(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if network.num_addresses <= 2:
        return network.network_address

    digest = hashlib.sha256(str(network).encode("ascii")).digest()
    offset = int.from_bytes(digest, "big") % (network.num_addresses - 2) + 1
    return network.network_address + offset


def lookup_region(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network, token: str
) -> str | None:
    return lookup_city(sampled_address(network), token)


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


def file_stem(location: str) -> str:
    sanitized = INVALID_FILENAME_CHARS.sub("_", location).strip(". ")
    sanitized = WHITESPACE.sub("_", sanitized)
    return sanitized or "Unknown"


def split_network(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    lookup_prefix = IPV4_LOOKUP_PREFIX if network.version == 4 else IPV6_LOOKUP_PREFIX
    if network.prefixlen >= lookup_prefix:
        yield network
        return
    yield from network.subnets(new_prefix=lookup_prefix)


def collapse_networks(
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> set[str]:
    return {str(network) for network in ipaddress.collapse_addresses(networks)}


def classify(
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network], token: str
) -> tuple[DefaultDict[str, set[str]], DefaultDict[str, set[str]]]:
    subnetworks = sorted(
        {subnetwork for network in networks for subnetwork in split_network(network)},
        key=lambda network: (network.version, int(network.network_address), network.prefixlen),
    )

    with ThreadPoolExecutor(max_workers=LOOKUP_WORKERS) as executor:
        locations = list(executor.map(lambda network: lookup_region(network, token), subnetworks))

    ipv4_by_location: DefaultDict[str, list[ipaddress.IPv4Network]] = defaultdict(list)
    ipv6_by_location: DefaultDict[str, list[ipaddress.IPv6Network]] = defaultdict(list)
    skipped_ipv4 = 0
    skipped_ipv6 = 0

    for network, location in zip(subnetworks, locations):
        if location is None:
            if network.version == 4:
                skipped_ipv4 += 1
            else:
                skipped_ipv6 += 1
            continue
        if network.version == 4:
            ipv4_by_location[location].append(network)
        else:
            ipv6_by_location[location].append(network)

    print(
        f"Skipped {skipped_ipv4} IPv4 and {skipped_ipv6} IPv6 subnets outside mainland China or without city data.",
        file=sys.stderr,
    )
    return (
        defaultdict(set, {
            location: collapse_networks(items)
            for location, items in ipv4_by_location.items()
        }),
        defaultdict(set, {
            location: collapse_networks(items)
            for location, items in ipv6_by_location.items()
        }),
    )


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
