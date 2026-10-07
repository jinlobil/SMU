"""FQDN object matching; DNS is optional topology information, never policy evidence."""
from __future__ import annotations

import ipaddress
import queue
import re
import socket
import threading


def normalize_fqdn(value: str, *, wildcard: bool = False) -> str:
    value = value.strip().removesuffix('.').casefold()
    prefix = '*.' if wildcard and value.startswith('*.') else ''
    value = value[2:] if prefix else value
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Destination FQDN 형식을 확인하세요') from exc
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise ValueError('Destination IP / CIDR 또는 FQDN 형식을 확인하세요')
    if all(label.isdigit() for label in labels):
        raise ValueError('Destination IP 형식을 확인하세요')
    return prefix + value


def fqdn_matches(query: str, pattern: str) -> bool:
    try:
        pattern = normalize_fqdn(pattern, wildcard=True)
        query = normalize_fqdn(query)
    except ValueError:
        return False
    if pattern.startswith('*.'):
        # A complete DNS label boundary; the bare apex is not a subdomain.
        return query.endswith('.' + pattern[2:])
    return query == pattern


_DNS_SLOTS = threading.BoundedSemaphore(4)


def resolve_fqdn(value: str, timeout: float = 2.0) -> list[str]:
    """Bound DNS latency/concurrency without changing process-wide socket settings."""
    if not _DNS_SLOTS.acquire(blocking=False):
        return []
    result: queue.Queue = queue.Queue(maxsize=1)
    def resolve():
        try:
            records = socket.getaddrinfo(value, None, type=socket.SOCK_STREAM)
            result.put(list(dict.fromkeys(str(ipaddress.ip_address(record[4][0])) for record in records)))
        except (OSError, ValueError):
            result.put([])
        finally:
            _DNS_SLOTS.release()
    threading.Thread(target=resolve, daemon=True).start()
    try:
        return result.get(timeout=timeout)
    except queue.Empty:
        return []
