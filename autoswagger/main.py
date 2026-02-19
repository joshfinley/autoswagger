"""CLI entry point, scan orchestration, signal handling, and output formatting."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from returns.io import IOFailure
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from autoswagger.http import RateLimiter, create_session
from autoswagger.models import EndpointResult, ScanConfig, ScanStats
from autoswagger.scanner import (
    discover_spec,
    extract_base_path,
    extract_endpoints,
    test_all_endpoints,
)

logger = logging.getLogger("autoswagger")
console = Console()

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------


def setup_logging(verbose: bool) -> None:
    """Configure logging with Rich console handler and optional file handler."""
    root_logger = logging.getLogger("autoswagger")
    root_logger.handlers.clear()

    console_handler = RichHandler(
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        console=console,
    )
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    root_logger.addHandler(console_handler)

    if verbose:
        log_dir = Path.home() / ".autoswagger" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(
            log_dir / datetime.now(tz=UTC).strftime("%Y-%m-%d_%H-%M-%S-log.txt"),
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root_logger.addHandler(file_handler)

    root_logger.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def print_banner() -> None:
    banner = """[white]
      /   | __  __/ /_____  ______      ______ _____ _____ ____  _____
     / /| |/ / / / __/ __ \\/ ___/ | /| / / __ `/ __ `/ __ `/ _ \\/ ___/
    / ___ / /_/ / /_/ /_/ (__  )| |/ |/ / /_/ / /_/ / /_/ /  __/ /
    /_/  |_\\__,_/\\__/\\____/____/ |__/|__/_\\__,_/\\__, /\\__, /\\___/_/
                                              /____//____/[/white]
                              [yellow]https://intruder.io[/yellow]
                          Find unauthenticated endpoints
    """
    console.print(banner)


# ---------------------------------------------------------------------------
# URL processing
# ---------------------------------------------------------------------------


def _process_input(urls: list[str]) -> list[str]:
    """Ensure each URL has a scheme."""
    processed: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        processed.append("https://" + url if not parsed.scheme else url)
    return processed


# ---------------------------------------------------------------------------
# Single URL processing
# ---------------------------------------------------------------------------

_stats_lock = threading.Lock()


def process_single_url(
    base_url: str,
    config: ScanConfig,
    session: Any,
    rate_limiter: RateLimiter,
    stats: ScanStats,
    cancel_event: threading.Event,
    bad_hosts: set[str] | None = None,
) -> list[EndpointResult]:
    """Scan one URL: discover spec → test endpoints. Flat control flow."""
    with _stats_lock:
        stats.active_hosts += 1

    spec_result = discover_spec(session, base_url, rate_limiter, cancel_event)
    if isinstance(spec_result, IOFailure):
        logger.info("No spec found for %s", base_url)
        if bad_hosts is not None:
            with _stats_lock:
                bad_hosts.add(urlparse(base_url).netloc)
        return []

    spec = spec_result.unwrap()._inner_value
    with _stats_lock:
        stats.hosts_with_valid_spec += 1

    if not config.product_mode:
        logger.info("Spec identified. Scanning endpoints.")

    base_path = extract_base_path(spec)
    endpoints = extract_endpoints(spec)

    results = test_all_endpoints(
        session, base_url, base_path, endpoints, rate_limiter,
        cancel_event, config.include_all, config.brute, config.timeout,
    )

    _update_stats_from_results(stats, results)
    return results


def _update_stats_from_results(stats: ScanStats, results: list[EndpointResult]) -> None:
    """Update stats with results from a single URL scan."""
    if not results:
        return
    with _stats_lock:
        stats.hosts_with_valid_endpoint += 1
        for r in results:
            if r.has_sensitive_data:
                stats.hosts_with_pii += 1
                for pf in r.pii_findings:
                    stats.pii_detection_methods.add(pf.detection_method)
                for sf in r.secret_findings:
                    stats.regexes_found.add(sf.regex_pattern)
                break  # count host once


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------


def run_scan(config: ScanConfig) -> tuple[list[EndpointResult], ScanStats]:
    """
    Orchestrate the full scan: process URLs sequentially or with threads.
    Handles Ctrl+C for clean shutdown.
    """
    cancel_event = threading.Event()
    session = create_session(config.proxy, insecure=config.insecure)
    rate_limiter = RateLimiter(config.rate, cancel_event)
    processed_urls = _process_input(config.urls)

    stats = ScanStats(
        unique_hosts_provided=len({urlparse(u).netloc for u in processed_urls}),
    )
    all_results: list[EndpointResult] = []
    bad_hosts: set[str] = set()
    start_time = time.time()

    original_handler = signal.getsignal(signal.SIGINT)

    def _handle_sigint(signum: int, frame: Any) -> None:
        logger.warning("Ctrl+C received, shutting down...")
        cancel_event.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        if config.concurrency == 0:
            _run_sequential(processed_urls, config, session, rate_limiter, stats, cancel_event, all_results, bad_hosts)
        else:
            _run_threaded(processed_urls, config, session, rate_limiter, stats, cancel_event, all_results, bad_hosts)
    finally:
        signal.signal(signal.SIGINT, original_handler)
        stats.scan_duration_seconds = time.time() - start_time
        stats.total_requests_sent = rate_limiter.request_count
        if config.verbose:
            _write_bad_hosts(bad_hosts)

    return all_results, stats


def _run_sequential(
    urls: list[str],
    config: ScanConfig,
    session: Any,
    rate_limiter: RateLimiter,
    stats: ScanStats,
    cancel_event: threading.Event,
    all_results: list[EndpointResult],
    bad_hosts: set[str],
) -> None:
    """Process URLs one at a time."""
    if not config.product_mode:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Processing URLs", total=len(urls))
            for url in urls:
                if cancel_event.is_set():
                    break
                results = process_single_url(url, config, session, rate_limiter, stats, cancel_event, bad_hosts)
                all_results.extend(results)
                progress.update(task, advance=1)
    else:
        for url in urls:
            if cancel_event.is_set():
                break
            results = process_single_url(url, config, session, rate_limiter, stats, cancel_event, bad_hosts)
            all_results.extend(results)


def _run_threaded(
    urls: list[str],
    config: ScanConfig,
    session: Any,
    rate_limiter: RateLimiter,
    stats: ScanStats,
    cancel_event: threading.Event,
    all_results: list[EndpointResult],
    bad_hosts: set[str],
) -> None:
    """Process URLs with a thread pool."""
    results_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=config.concurrency) as executor:
        futures = {
            executor.submit(process_single_url, url, config, session, rate_limiter, stats, cancel_event, bad_hosts): url
            for url in urls
        }

        if not config.product_mode:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Processing URLs", total=len(futures))
                for future in as_completed(futures):
                    if cancel_event.is_set():
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        results = future.result(timeout=1.0)
                        with results_lock:
                            all_results.extend(results)
                    except Exception as exc:
                        logger.debug("Error processing %s: %s", futures[future], exc)
                    progress.update(task, advance=1)
        else:
            for future in as_completed(futures):
                if cancel_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    results = future.result(timeout=1.0)
                    with results_lock:
                        all_results.extend(results)
                except Exception as exc:
                    logger.debug("Error processing %s: %s", futures[future], exc)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def deduplicate_results(results: list[EndpointResult]) -> list[EndpointResult]:
    """Group by (method, path_template), keep highest content_length."""
    grouped: dict[tuple[str, str], EndpointResult] = {}
    for r in results:
        key = (r.method, r.path_template)
        existing = grouped.get(key)
        if existing is None or r.content_length > existing.content_length:
            grouped[key] = r
    deduped = list(grouped.values())
    deduped.sort(key=lambda x: (-x.content_length, not x.has_sensitive_data))
    return deduped


def _filter_results(results: list[EndpointResult], include_all: bool, product_mode: bool) -> list[EndpointResult]:
    """Filter results based on mode."""
    if product_mode:
        return [r for r in results if r.has_sensitive_data or r.is_interesting]
    if include_all:
        return [r for r in results if r.status_code not in (401, 403)]
    return [r for r in results if r.status_code == 200]


def format_table_output(results: list[EndpointResult], stats: ScanStats | None) -> None:
    """Render results as a Rich table."""
    if not results:
        logger.info("No valid API responses found.")
        return

    table = Table(title="API Endpoints", show_lines=False)
    table.add_column("Method", style="cyan", no_wrap=True)
    table.add_column("URL", style="magenta", overflow="fold")
    table.add_column("Status Code", style="green")
    table.add_column("Content Length", style="yellow")
    table.add_column("PII or Secret Detected", style="red")

    for r in results:
        table.add_row(
            r.method,
            r.url,
            str(r.status_code),
            f"{r.content_length:,}",
            "Yes" if r.has_sensitive_data else "No",
        )

    console.print(table)

    if stats is not None:
        _print_stats_table(stats)


def _print_stats_table(stats: ScanStats) -> None:
    """Render scan statistics as a Rich table."""
    stats_table = Table(title="Scan Statistics", show_lines=False)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="magenta")

    data = stats.to_dict()
    data["percentage_hosts_with_endpoint"] = f"{data['percentage_hosts_with_endpoint']}%"
    data["pii_detection_methods"] = ", ".join(data["pii_detection_methods"])
    data["regexes_found"] = ", ".join(data["regexes_found"])

    for k, v in data.items():
        if isinstance(v, float):
            display = f"{v:.2f}"
        elif isinstance(v, int):
            display = f"{v:,}"
        else:
            display = str(v)
        stats_table.add_row(k.replace("_", " ").title(), display)

    console.print(stats_table)


def format_json_output(
    results: list[EndpointResult],
    stats: ScanStats | None,
) -> None:
    """Render results as JSON."""
    result_dicts = [r.to_dict() for r in results]
    output: dict[str, Any] = {"results": result_dicts}
    if stats is not None:
        output["stats"] = stats.to_dict()
    console.print_json(data=output)


# ---------------------------------------------------------------------------
# Bad hosts tracking
# ---------------------------------------------------------------------------


def _write_bad_hosts(bad_hosts: set[str]) -> None:
    """Write hosts with no valid spec to a log file."""
    if not bad_hosts:
        return
    bad_hosts_file = Path.home() / ".autoswagger" / "logs" / "bad-hosts.txt"
    bad_hosts_file.parent.mkdir(parents=True, exist_ok=True)
    with bad_hosts_file.open("a") as f:
        f.writelines(host + "\n" for host in bad_hosts)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def cli() -> None:
    """Parse arguments, run scan, format output."""
    parser = argparse.ArgumentParser(
        description="Autoswagger: Detect unauthenticated access control issues via Swagger/OpenAPI documentation.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example usage:\n  python -m autoswagger https://api.example.com -v",
    )
    parser.add_argument("urls", nargs="*", help="Base URL(s) or spec URL(s) of the target API(s)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--all", action="store_true", help="Include 404 responses (still excludes 401/403)")
    parser.add_argument("--product", action="store_true", help="Output only PII/large-response endpoints as JSON")
    parser.add_argument("--stats", action="store_true", help="Display scan statistics")
    parser.add_argument("--rate", type=int, default=15, help="Requests per second (default: 15, max: 15)")
    parser.add_argument("-b", "--brute", action="store_true", help="Brute-force parameter values")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--proxy", type=str, default=None, help="HTTP proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--concurrency", type=int, default=0, help="Thread count (default: 0 = sequential)")

    args = parser.parse_args()

    if args.rate < 1 or args.rate > 15:
        parser.error("Rate must be between 1 and 15 requests per second")

    # Support stdin piping
    urls: list[str] = args.urls
    if not urls and not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]

    if not urls:
        print_banner()
        parser.print_help()
        sys.exit()

    config = ScanConfig(
        urls=urls,
        verbose=args.verbose,
        include_all=args.all,
        product_mode=args.product,
        stats_flag=args.stats,
        rate=args.rate,
        brute=args.brute,
        json_output=args.json,
        proxy=args.proxy,
        insecure=args.insecure,
        concurrency=args.concurrency,
    )

    setup_logging(config.verbose)

    if not config.product_mode:
        print_banner()

    all_results, stats = run_scan(config)

    # Deduplicate and filter
    results = deduplicate_results(all_results)
    results = _filter_results(results, config.include_all, config.product_mode)

    # Output
    if config.product_mode or config.json_output:
        format_json_output(
            results,
            stats if config.stats_flag else None,
        )
    else:
        format_table_output(
            results,
            stats if config.stats_flag else None,
        )
