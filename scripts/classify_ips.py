#!/usr/bin/env python3
"""Classify CIDR ranges by GeoLite2 city and write per-city IP lists."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import DefaultDict, Iterable

import geoip2.database
from geoip2.errors import AddressNotFoundError


INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WHITESPACE = re.compile(r'\s+')


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify IPv4 and IPv6 CIDRs into city-specific text files."
    )
    parser.add_argument("--input", required=True, type=Path, help="Input CIDR list")
    parser.add_argument("--database", required=True, type=Path, help="GeoLite2 City MMDB")
    parser.add_argument("--output-dir", required=True, type=Path, help="Output directory")
    return parser.parse_args()


def city_name(record: geoip2.models.City) -> str:
    for candidate in (
        record.city.names.get("en"),
        record.city.name,
        record.subdivisions.most_specific.names.get("en"),
        record.subdivisions.most_specific.name,
        record.country.names.get("en"),
        record.country.name,
        "Unknown",
    ):
        if candidate:
            return candidate
    return "Unknown"


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
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network], database_path: Path
) -> tuple[DefaultDict[str, set[str]], DefaultDict[str, set[str]]]:
    ipv4_by_city: DefaultDict[str, set[str]] = defaultdict(set)
    ipv6_by_city: DefaultDict[str, set[str]] = defaultdict(set)

    with geoip2.database.Reader(str(database_path), locales=["en"]) as reader:
        for network in networks:
            try:
                location = city_name(reader.city(str(network.network_address)))
            except AddressNotFoundError:
                location = "Unknown"

            target = ipv4_by_city if network.version == 4 else ipv6_by_city
            target[location].add(str(network))

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
        if ipv4:
            write_list(output_dir / f"{stem}-4.txt", ipv4)
        if ipv6:
            write_list(output_dir / f"{stem}-6.txt", ipv6)
        write_list(output_dir / f"{stem}-46.txt", ipv4 | ipv6)


def main() -> int:
    args = parse_arguments()
    if not args.input.is_file():
        print(f"Input file not found: {args.input}", file=sys.stderr)
        return 1
    if not args.database.is_file():
        print(f"GeoLite2 database not found: {args.database}", file=sys.stderr)
        return 1

    ipv4_by_city, ipv6_by_city = classify(read_networks(args.input), args.database)
    write_output(args.output_dir, ipv4_by_city, ipv6_by_city)
    print(f"Wrote {len(set(ipv4_by_city) | set(ipv6_by_city))} location groups.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
