"""HTTP transport: rate limiter, session factory, and the single GET choke point."""

from __future__ import annotations

import logging
import threading
import time

import requests
import urllib3
from returns.io import impure_safe

logger = logging.getLogger("autoswagger")

TIMEOUT: int = 10


# ---------------------------------------------------------------------------
# Rate limiter (token bucket, thread-safe)
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe token-bucket rate limiter with cancellation support."""

    def __init__(self, rate: int, cancel_event: threading.Event | None = None) -> None:
        self._rate = rate
        self._cancel_event = cancel_event
        self._tokens: float = 0.0
        self._max_tokens: float = float(rate)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()
        self._request_count: int = 0
        self._count_lock = threading.Lock()

    @property
    def request_count(self) -> int:
        with self._count_lock:
            return self._request_count

    def _increment_count(self) -> None:
        with self._count_lock:
            self._request_count += 1

    def acquire(self) -> bool:
        """Block until a token is available. Returns False if cancelled."""
        while True:
            if self._cancel_event is not None and self._cancel_event.is_set():
                return False

            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._max_tokens, self._tokens + elapsed * self._rate)
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    self._increment_count()
                    return True

            wait_time = min(1.0 / self._rate, 0.1)
            if self._cancel_event is not None:
                self._cancel_event.wait(timeout=wait_time)
            else:
                time.sleep(wait_time)


# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------


def create_session(proxy: str | None = None, insecure: bool = False) -> requests.Session:
    """Create a requests.Session with proxy and SSL config."""
    session = requests.Session()
    session.headers.update({"User-Agent": "Autoswagger/2.0"})
    if insecure:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


# ---------------------------------------------------------------------------
# Single GET choke point
# ---------------------------------------------------------------------------


@impure_safe
def http_get(
    session: requests.Session,
    url: str,
    rate_limiter: RateLimiter,
    timeout: int = TIMEOUT,
    allow_redirects: bool = False,
) -> requests.Response:
    """All HTTP GET traffic flows through this function."""
    if not rate_limiter.acquire():
        msg = "Request cancelled"
        raise InterruptedError(msg)
    return session.get(url, allow_redirects=allow_redirects, timeout=timeout)
