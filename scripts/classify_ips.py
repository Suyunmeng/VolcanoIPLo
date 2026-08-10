#!/usr/bin/env python3
"""Classify CIDR ranges by mainland city using the IPinfo API."""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import DefaultDict, Iterable, Sequence

import requests


IPINFO_LOOKUP_URL = "https://ipinfo.io/"
REQUEST_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 6
LOOKUP_WORKERS = 64
RETRY_DELAY_CAP_SECONDS = 30
SESSION_LOCAL = threading.local()
TOKEN_LOCK = threading.Lock()
EXHAUSTED_TOKENS: set[str] = set()
IPV4_LOOKUP_PREFIX = 24
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WHITESPACE = re.compile(r'\s+')


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify CIDR ranges by mainland city using the IPinfo API."
    )
    parser.add_argument("--input", required=True, type=Path, help="Input CIDR list")
    parser.add_argument("--token", required=True, help="Comma-separated IPinfo API tokens")
    parser.add_argument("--output-dir", required=True, type=Path, help="Output directory")
    return parser.parse_args()


def parse_tokens(value: str) -> tuple[str, ...]:
    tokens = tuple(dict.fromkeys(token.strip() for token in value.split(",") if token.strip()))
    if not tokens:
        raise ValueError("IPinfo API token list must not be empty")
    return tokens


def next_token(tokens: Sequence[str]) -> str:
    with TOKEN_LOCK:
        for token in tokens:
            if token not in EXHAUSTED_TOKENS:
                return token
    raise RuntimeError("All IPinfo API tokens have been rate-limited.")


def mark_token_exhausted(token: str) -> None:
    with TOKEN_LOCK:
        EXHAUSTED_TOKENS.add(token)


def city_name(response: dict[str, object]) -> str | None:
    if response.get("country") != "CN":
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


def retry_delay(response: requests.Response | None, attempt: int) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return min(int(retry_after), RETRY_DELAY_CAP_SECONDS)
    return min(2**attempt, RETRY_DELAY_CAP_SECONDS)


def session() -> requests.Session:
    current = getattr(SESSION_LOCAL, "session", None)
    if current is None:
        current = requests.Session()
        current.headers.update({"Accept": "application/json"})
        SESSION_LOCAL.session = current
    return current


def lookup_city(address: ipaddress.IPv4Address | ipaddress.IPv6Address, tokens: Sequence[str]) -> str | None:
    url = f"{IPINFO_LOOKUP_URL}{address}/json"
    token: str | None = None
    transient_attempt = 0

    while True:
        if token is None:
            token = next_token(tokens)

        response: requests.Response | None = None
        try:
            response = session().get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code in (400, 404):
                return None
            if response.status_code in (401, 403):
                raise RuntimeError(
                    "IPinfo rejected an API token. Verify the IPINFO_TOKEN repository secret."
                )
            if response.status_code == 429:
                mark_token_exhausted(token)
                token = None
                continue
            if response.status_code >= 500:
                response.raise_for_status()
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise RuntimeError("IPinfo returned a non-object JSON response")
            return city_name(payload)
        except requests.HTTPError as error:
            if error.response is None or error.response.status_code < 500:
                raise RuntimeError(
                    f"IPinfo lookup failed for {address}: HTTP {error.response.status_code}"
                ) from error
            last_error: Exception = error
        except (requests.ConnectionError, requests.Timeout, requests.JSONDecodeError) as error:
            last_error = error

        transient_attempt += 1
        if transient_attempt == MAX_ATTEMPTS:
            raise RuntimeError(f"IPinfo lookup failed for {address}: {last_error}") from last_error
        time.sleep(retry_delay(response, transient_attempt - 1))


def sampled_address(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if network.num_addresses == 1:
        return network.network_address
    return network.network_address + 1


def lookup_region(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network, tokens: Sequence[str]
) -> str | None:
    return lookup_city(sampled_address(network), tokens)


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
    if network.version == 6 or network.prefixlen >= IPV4_LOOKUP_PREFIX:
        yield network
        return
    yield from network.subnets(new_prefix=IPV4_LOOKUP_PREFIX)


def collapse_networks(
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> set[str]:
    return {str(network) for network in ipaddress.collapse_addresses(networks)}


def classify(
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network], tokens: Sequence[str]
) -> tuple[DefaultDict[str, set[str]], DefaultDict[str, set[str]]]:
    subnetworks = sorted(
        {subnetwork for network in networks for subnetwork in split_network(network)},
        key=lambda network: (network.version, int(network.network_address), network.prefixlen),
    )

    with ThreadPoolExecutor(max_workers=LOOKUP_WORKERS) as executor:
        locations = list(executor.map(lambda network: lookup_region(network, tokens), subnetworks))

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

    try:
        tokens = parse_tokens(args.token)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    ipv4_by_city, ipv6_by_city = classify(read_networks(args.input), tokens)
    write_output(args.output_dir, ipv4_by_city, ipv6_by_city)
    print(f"Wrote {len(set(ipv4_by_city) | set(ipv6_by_city))} location groups.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
