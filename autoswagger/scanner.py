"""Spec discovery and endpoint testing."""

from __future__ import annotations

import json
import logging
import re
import threading
from itertools import product as itertools_product
from typing import Any, cast
from urllib.parse import urlencode, urljoin, urlparse

import requests
import yaml
from bs4 import BeautifulSoup
from returns.io import IOFailure, IOResultE, IOSuccess, impure_safe
from returns.result import Failure, Success, safe

from autoswagger.analysis import analyze_response
from autoswagger.http import TIMEOUT, RateLimiter, http_get
from autoswagger.models import EndpointResult, SpecEndpoint

logger = logging.getLogger("autoswagger")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SWAGGER_UI_PATHS: list[str] = sorted({
    "/", "/apidocs/", "/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html",
    "/swagger/swagger-ui.html", "/api/swagger-ui.html", "/api_docs", "/api/index.html",
    "/api/doc", "/api/docs/", "/api/swagger/index.html", "/api/swagger/swagger-ui.html",
    "/api/swagger-ui/api-docs", "/api/api-docs", "/api/apidocs", "/api/swagger",
    "/api/swagger/static/index.html", "/api/swagger-resources",
    "/api/swagger-resources/restservices/v2/api-docs", "/api/__swagger__/", "/api/_swagger_/",
    "/docu", "/docs", "/swagger", "/api-doc", "/doc/",
    "/webjars/swagger-ui/index.html", "/3.0.0/swagger-ui.html",
    "/MobiControl/api/docs/index/index.html", "/Swagger", "/Swagger/", "/Swagger/index.html",
    "/V2/api-docs/ui", "/admin/swagger-ui/index.html", "/api-doc/", "/api-docs/",
    "/api-docs/ui/", "/api-docs/v1/index.html", "/api-documentation/index.html",
    "/api/", "/api/api-docs/index.html", "/api/api/",
    "/api/config", "/api/doc/", "/api/spec/", "/spec/",
    "/index.html", "/swagger-ui/", "/swagger-ui/index.html",
})

DIRECT_SPEC_PATHS: list[str] = sorted({
    "/swagger.json", "/swagger.yaml", "/swagger.yml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/swagger.yml", "/v1/swagger.json",
    "/v1/swagger.yaml", "/v1/swagger.yml", "/openapi.json",
    "/openapi.yaml", "/openapi.yml", "/api/openapi.json",
    "/api/openapi.yaml", "/api/openapi.yml", "/docs/swagger.json",
    "/docs/swagger.yaml", "/docs/openapi.json", "/docs/openapi.yaml",
    "/api-docs/swagger.json", "/api-docs/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
    "/rest/swagger.json", "/rest/swagger.yaml", "/rest-api/swagger.json",
    "/swagger/v1/docs.json", "/api/swagger/docs.json",
    "/swagger/docs/v1.json", "/swagger/swagger.json", "/swagger/swagger.yaml",
    "/api-doc.json", "/api/spec/swagger.json", "/api/spec/swagger.yaml",
    "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
    "/api/swagger_doc.json", "/v2/swagger.json", "/v2/swagger.yaml",
    "/v3/swagger.json", "/v3/swagger.yaml", "/openapi2.json",
    "/openapi2.yaml", "/openapi2.yml", "/api/v3/openapi.json",
    "/api/v3/openapi.yaml", "/api/v3/openapi.yml", "/spec/swagger.json",
    "/spec/swagger.yaml", "/spec/openapi.json", "/spec/openapi.yaml",
    "/api-docs/swagger-ui.json", "/api-docs/swagger-ui.yaml",
    "/api-docs/openapi.json", "/api-docs/openapi.yaml",
    "/swagger-ui.json", "/swagger-ui.yaml",
})

TEST_VALUES: dict[str, list[Any]] = {
    "integer": [1, 2, 100, -1, 0, 999, 123456],
    "string": [
        "1", "test", "example", "1234", "none", "admin", "guest",
        "user@email.com",
        "550e8400-e29b-41d4-a716-446655440000",
        "a8098c1a-f86e-11da-bd1a-00112444be1e",
    ],
    "boolean": [True, False],
    "number": [1, 0, 100, 1000, 0.1],
    "base64": ["MQ==", "dXNlcjE=", "YWRtaW4xMjM=", "c2FtcGxlVXNlcg=="],
    "default": [
        "1", "test", "123", "True", "true",
        "550e8400-e29b-41d4-a716-446655440000", "*", "All",
    ],
}


# ---------------------------------------------------------------------------
# Spec parsing helpers (pure, @safe)
# ---------------------------------------------------------------------------


@safe
def parse_spec_content(content: str, content_type: str) -> dict[str, Any]:
    """Parse a JSON or YAML string into a spec dict."""
    if "json" in content_type:
        return cast("dict[str, Any]", json.loads(content))
    return cast("dict[str, Any]", yaml.safe_load(content))


@safe
def extract_spec_url_from_html(html_text: str) -> str:
    """Extract swagger spec URL from HTML content."""
    matches = re.findall(r'url:\s*["\'](.*?)["\']', html_text)
    if matches:
        return cast("str", matches[0])

    matches = re.findall(
        r'SwaggerUIBundle\s*\(\s*{\s*url:\s*"(.*?)"', html_text, re.DOTALL,
    )
    if matches:
        return cast("str", matches[0])

    soup = BeautifulSoup(html_text, "html.parser")
    for script in soup.find_all("script"):
        sc = script.string
        if sc and "url:" in sc:
            mm = re.findall(r'url:\s*"(.*?)"', sc)
            if mm:
                return cast("str", mm[0])

    msg = "No spec URL found in HTML"
    raise ValueError(msg)


@safe
def extract_spec_url_from_js(js_text: str) -> str:
    """Extract swagger spec URL from JavaScript source."""
    patterns = [
        r'url:\s*["\'](.*?)["\']',
        r'urls:\s*\[\s*{\s*url:\s*["\'](.*?)["\']',
        r'const\s+\w+\s*=\s*["\'](.*?)["\']',
        r'defaultDefinitionUrl\s*=\s*["\'](.*?)["\']',
        r'definitionURL\s*=\s*["\'](.*?)["\']',
    ]
    for pat in patterns:
        matches = re.findall(pat, js_text)
        if matches:
            return cast("str", matches[0])
    msg = "No spec URL found in JS"
    raise ValueError(msg)


@safe
def extract_spec_from_js(js_text: str) -> dict[str, Any]:
    """Extract an embedded spec object from JavaScript source."""
    cleaned = re.sub(r"/\*[\s\S]*?\*/", "", js_text)
    cleaned = re.sub(r"//.*", "", cleaned)

    patterns = [
        r"(?:var|let|const)\s+(\w+)\s*=\s*({[\s\S]*?});",
        r"(\w+)\s*=\s*({[\s\S]*?});",
    ]
    for pat in patterns:
        matches = re.findall(pat, cleaned, re.DOTALL)
        for _var_name, obj_str in matches:
            json_result = _js_object_to_json(obj_str)
            if isinstance(json_result, Success):
                json_str: str = json_result.unwrap()
                spec = json.loads(json_str)
                if isinstance(spec, dict):
                    return cast("dict[str, Any]", spec)
    msg = "No embedded spec found in JS"
    raise ValueError(msg)


@safe
def extract_swashbuckle_config_spec_url(html_text: str) -> str:
    """Extract discoveryPaths from swashbuckleConfig."""
    match = re.search(r"window\.swashbuckleConfig\s*=\s*{([\s\S]*?)};", html_text)
    if not match:
        msg = "No swashbuckleConfig found"
        raise ValueError(msg)
    config_content = match.group(1)
    disc_paths = re.findall(
        r"discoveryPaths\s*:\s*\[\s*[\"'](.*?)[\"']\s*\]", config_content,
    )
    if disc_paths:
        return cast("str", disc_paths[0])
    msg = "No discoveryPaths in swashbuckleConfig"
    raise ValueError(msg)


@safe
def _js_object_to_json(js_object_str: str) -> str:
    """Convert JS object literal to valid JSON string."""
    s = js_object_str.strip()
    s = re.sub(r"'", '"', s)
    s = re.sub(r"([{,]\s*)(\w+)\s*:", r'\1"\2":', s)
    s = re.sub(r",\s*([}\]])", r"\1", s)
    json.loads(s)  # validate
    return s


# ---------------------------------------------------------------------------
# Spec discovery (flattened from 13 levels to max 3 per function)
# ---------------------------------------------------------------------------


def _has_spec_extension(url: str) -> bool:
    return any(url.lower().endswith(ext) for ext in (".json", ".yaml", ".yml"))


def _is_local_js_file(js_file_url: str, base_url: str) -> bool:
    parsed_js = urlparse(js_file_url)
    parsed_base = urlparse(base_url)
    return not parsed_js.netloc or parsed_js.netloc == parsed_base.netloc


def _page_mentions_swagger(text: str) -> bool:
    lower = text.lower()
    return "swagger" in lower or "openapi" in lower


def _fetch_or_extract_from_url(
    session: requests.Session,
    url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Given a discovered URL, fetch it as a spec or try JS extraction."""
    if _has_spec_extension(url):
        result = _fetch_and_validate_spec(session, url, rate_limiter)
        if isinstance(result, IOSuccess):
            return cast("dict[str, Any]", result.unwrap()._inner_value)
        return None

    if url.lower().endswith(".js"):
        return _try_embedded_spec_from_js_url(session, url, rate_limiter)

    return None


def _try_embedded_spec_from_js_url(
    session: requests.Session,
    js_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Fetch a JS file and try to extract an embedded spec."""
    response_result = http_get(session, js_url, rate_limiter)
    if isinstance(response_result, IOFailure):
        return None
    response: requests.Response = response_result.unwrap()._inner_value
    spec_result = extract_spec_from_js(response.text)
    if isinstance(spec_result, Success):
        return cast("dict[str, Any]", spec_result.unwrap())
    return None


def _try_spec_url_from_html(
    session: requests.Session,
    html_text: str,
    page_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Try to extract a spec URL from HTML and fetch it."""
    url_result = extract_spec_url_from_html(html_text)
    if isinstance(url_result, Failure):
        return None
    spec_url = urljoin(page_url, cast("str", url_result.unwrap()))
    logger.debug("Found spec URL in HTML: %s", spec_url)
    return _fetch_or_extract_from_url(session, spec_url, rate_limiter)


def _try_spec_from_js_files(
    session: requests.Session,
    html_text: str,
    page_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Scan <script> tags for local JS files and try to extract spec."""
    js_files = re.findall(r'<script\s+src=["\']([^"\']+\.js)["\']', html_text, re.IGNORECASE)
    js_files = [x for x in js_files if _is_local_js_file(x, page_url)]
    js_files_sorted = sorted(js_files, key=lambda x: "init" in x.lower(), reverse=True)

    for jsf in js_files_sorted:
        jsu = urljoin(page_url, jsf)
        logger.debug("Fetching JS file: %s", jsu)
        resp_result = http_get(session, jsu, rate_limiter)
        if isinstance(resp_result, IOFailure):
            continue
        js_response: requests.Response = resp_result.unwrap()._inner_value
        js_text = js_response.text

        # Try extracting a spec URL from the JS
        js_url_result = extract_spec_url_from_js(js_text)
        if isinstance(js_url_result, Success):
            full_url = urljoin(jsu, cast("str", js_url_result.unwrap()))
            logger.debug("Found spec URL in JS: %s", full_url)
            spec = _fetch_or_extract_from_url(session, full_url, rate_limiter)
            if spec is not None:
                return spec

        # Try extracting an embedded spec from the JS
        emb_result = extract_spec_from_js(js_text)
        if isinstance(emb_result, Success):
            logger.debug("Extracted embedded spec from JS: %s", jsu)
            return cast("dict[str, Any]", emb_result.unwrap())

    return None


def _try_swashbuckle_config(
    session: requests.Session,
    html_text: str,
    page_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Try to find a spec via swashbuckleConfig."""
    url_result = extract_swashbuckle_config_spec_url(html_text)
    if isinstance(url_result, Failure):
        return None
    full_url = urljoin(page_url, cast("str", url_result.unwrap()))
    logger.debug("Found spec URL via swashbuckleConfig: %s", full_url)
    result = _fetch_and_validate_spec(session, full_url, rate_limiter)
    if isinstance(result, IOSuccess):
        return cast("dict[str, Any]", result.unwrap()._inner_value)
    return None


def _try_extract_spec_from_page(
    session: requests.Session,
    html_text: str,
    page_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any] | None:
    """Try all extraction strategies for a single Swagger UI page."""
    spec = _try_spec_url_from_html(session, html_text, page_url, rate_limiter)
    if spec is not None:
        return spec

    spec = _try_spec_from_js_files(session, html_text, page_url, rate_limiter)
    if spec is not None:
        return spec

    spec = _try_swashbuckle_config(session, html_text, page_url, rate_limiter)
    if spec is not None:
        return spec

    return None


def _fetch_and_validate_spec(
    session: requests.Session,
    url: str,
    rate_limiter: RateLimiter,
) -> IOResultE[dict[str, Any]]:
    """Fetch URL via http_get and parse as spec. All traffic goes through the choke point."""
    resp_result = http_get(session, url, rate_limiter)
    if isinstance(resp_result, IOFailure):
        return resp_result

    response: requests.Response = resp_result.unwrap()._inner_value
    if response.status_code != 200:
        return IOFailure(ValueError(f"Non-200 status: {response.status_code}"))

    ctype = response.headers.get("Content-Type", "").lower()
    if not any(x in ctype for x in ("json", "yaml", "text/plain")):
        return IOFailure(ValueError(f"Unexpected content type: {ctype}"))

    text_lower = response.text.lower()
    if "swagger" not in text_lower and "openapi" not in text_lower:
        return IOFailure(ValueError("Response does not contain swagger/openapi keywords"))

    spec_result = parse_spec_content(response.text, ctype)
    if isinstance(spec_result, Failure):
        return IOFailure(spec_result.failure())

    return IOSuccess(spec_result.unwrap())


@impure_safe
def find_swagger_ui_docs(
    session: requests.Session,
    base_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any]:
    """Probe SWAGGER_UI_PATHS and extract spec. Max nesting: 3."""
    for path in SWAGGER_UI_PATHS:
        url = urljoin(base_url, path)
        logger.debug("Checking Swagger UI at %s", url)
        resp_result = http_get(session, url, rate_limiter)
        if isinstance(resp_result, IOFailure):
            continue
        response: requests.Response = resp_result.unwrap()._inner_value
        if response.status_code != 200:
            continue
        if not _page_mentions_swagger(response.text):
            continue

        logger.debug("Swagger UI found at %s", url)
        spec = _try_extract_spec_from_page(session, response.text, url, rate_limiter)
        if spec is not None:
            return spec

    msg = f"No Swagger UI found for {base_url}"
    raise ValueError(msg)


@impure_safe
def discover_spec_by_direct_paths(
    session: requests.Session,
    base_url: str,
    rate_limiter: RateLimiter,
) -> dict[str, Any]:
    """Brute-force DIRECT_SPEC_PATHS for a spec."""
    for path in DIRECT_SPEC_PATHS:
        spec_url = urljoin(base_url, path)
        logger.debug("Trying direct path: %s", spec_url)
        result = _fetch_and_validate_spec(session, spec_url, rate_limiter)
        if isinstance(result, IOSuccess):
            logger.info("Spec found via direct path: %s", spec_url)
            return cast("dict[str, Any]", result.unwrap()._inner_value)

    msg = f"No spec found via direct paths for {base_url}"
    raise ValueError(msg)


def discover_spec(
    session: requests.Session,
    base_url: str,
    rate_limiter: RateLimiter,
    cancel_event: threading.Event,
) -> IOResultE[dict[str, Any]]:
    """
    Chain discovery strategies: direct URL → Swagger UI → brute-force paths.
    Checks cancel_event between phases.
    """
    # Strategy 1: URL is a direct spec
    if _has_spec_extension(base_url):
        result = _fetch_and_validate_spec(session, base_url, rate_limiter)
        if isinstance(result, IOSuccess):
            return result

    if cancel_event.is_set():
        return IOFailure(InterruptedError("Cancelled"))

    # Strategy 2: Swagger UI detection
    result = find_swagger_ui_docs(session, base_url, rate_limiter)
    if isinstance(result, IOSuccess):
        return result

    if cancel_event.is_set():
        return IOFailure(InterruptedError("Cancelled"))

    # Strategy 3: Brute-force direct paths
    result = discover_spec_by_direct_paths(session, base_url, rate_limiter)
    if isinstance(result, IOSuccess):
        return result

    return IOFailure(ValueError(f"No spec found for {base_url}"))


# ---------------------------------------------------------------------------
# Endpoint extraction and testing (GET only)
# ---------------------------------------------------------------------------


def extract_base_path(spec: dict[str, Any]) -> str:
    """Read basePath (Swagger 2) or servers[0].url (OpenAPI 3)."""
    if "servers" in spec and isinstance(spec["servers"], list) and spec["servers"]:
        return spec["servers"][0].get("url", "/")
    return spec.get("basePath", "/")


def extract_endpoints(spec: dict[str, Any]) -> list[SpecEndpoint]:
    """Extract all GET endpoints from a spec."""
    endpoints: list[SpecEndpoint] = []
    paths = spec.get("paths", {})
    if not paths:
        logger.warning("Specification does not contain 'paths' key.")
        return endpoints

    seen: set[str] = set()
    for path_template, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() != "get":
                continue
            if path_template in seen:
                continue
            seen.add(path_template)

            parameters = details.get("parameters", []) if isinstance(details, dict) else []
            endpoints.append(SpecEndpoint(
                path_template=path_template,
                parameters=tuple(parameters),
            ))

    return endpoints


# ---------------------------------------------------------------------------
# URL building helpers
# ---------------------------------------------------------------------------


def generate_parameter_values(param_type: str, enum: list[Any] | None = None) -> list[Any]:
    """Return test values for a parameter type."""
    if enum:
        return enum
    return TEST_VALUES.get(param_type, TEST_VALUES["default"])


def _resolve_param_type_and_enum(param: dict[str, Any]) -> tuple[str, list[Any] | None]:
    """
    Extract (type, enum) from a parameter dict, handling both
    Swagger 2.0 (type at top level) and OpenAPI 3.0 (type under schema).
    Also handles array types with items.enum (e.g. findByStatus?status=available).
    """
    # OpenAPI 3.0: type under "schema"
    schema = param.get("schema", {})
    ptype = schema.get("type") or param.get("type", "string")
    enum = schema.get("enum") or param.get("enum")

    # Array type: use the items' enum/type instead
    if ptype == "array":
        items = schema.get("items") or param.get("items", {})
        enum = items.get("enum", enum)
        ptype = items.get("type", "string")

    return ptype, enum


def build_value_mapping(parameters: tuple[dict[str, Any], ...], value_index: int = 0) -> dict[str, Any]:
    """Create param_name -> test_value mapping from parameter schemas."""
    mapping: dict[str, Any] = {}
    for param in parameters:
        if param.get("in") not in ("path", "query"):
            continue
        name = param.get("name", "")
        ptype, enum = _resolve_param_type_and_enum(param)
        values = generate_parameter_values(ptype, enum)
        mapping[name] = values[value_index % len(values)]
    return mapping


def substitute_path_parameters(
    path: str,
    parameters: tuple[dict[str, Any], ...],
    value_mapping: dict[str, Any],
) -> str:
    """Replace {param}, :param, <param> placeholders."""
    for param in parameters:
        if param.get("in") != "path":
            continue
        name = param.get("name", "")
        value = value_mapping.get(name)
        if value is not None:
            path = re.sub(rf"{{{name}}}|:{name}|<{name}>", str(value), path)
    return path


def generate_query_string(
    parameters: tuple[dict[str, Any], ...],
    value_mapping: dict[str, Any],
) -> str:
    """Build ?key=value query string for query params."""
    query_params: dict[str, Any] = {}
    for param in parameters:
        if param.get("in") != "query":
            continue
        name = param.get("name", "")
        value = value_mapping.get(name)
        if value is not None:
            query_params[name] = value
    return urlencode(query_params)


def _build_full_url(base_url_no_path: str, path: str, query_string: str) -> str:
    """Construct the full request URL."""
    if not path.startswith("/"):
        path = "/" + path
    parsed = urlparse(path)
    full = path if parsed.scheme in ("http", "https") else urljoin(base_url_no_path, path)
    if query_string:
        full = f"{full}?{query_string}"
    return full


# ---------------------------------------------------------------------------
# Endpoint testing
# ---------------------------------------------------------------------------


def test_single_endpoint(
    session: requests.Session,
    base_url_no_path: str,
    full_path: str,
    endpoint: SpecEndpoint,
    rate_limiter: RateLimiter,
    include_all: bool,
    timeout: int = TIMEOUT,
) -> EndpointResult | None:
    """Test a single GET endpoint. Returns None for auth-required or failed requests."""
    value_mapping = build_value_mapping(endpoint.parameters)
    path = substitute_path_parameters(full_path, endpoint.parameters, value_mapping)
    qs = generate_query_string(endpoint.parameters, value_mapping)
    url = _build_full_url(base_url_no_path, path, qs)

    resp_result = http_get(session, url, rate_limiter, timeout)
    if isinstance(resp_result, IOFailure):
        logger.debug("Request failed for %s: %s", url, resp_result.failure())
        return None

    response: requests.Response = resp_result.unwrap()._inner_value
    status_code = response.status_code

    if status_code in (401, 403):
        logger.debug("Skipping %s due to status %d", url, status_code)
        return None

    content = response.text

    pii_findings, secret_findings, is_interesting = analyze_response(content)

    # Only mark interesting for 200 (or 404 if include_all)
    if status_code == 200 or (include_all and status_code == 404):
        pass  # keep is_interesting as computed
    else:
        is_interesting = False

    return EndpointResult(
        method="GET",
        url=url,
        path_template=endpoint.path_template,
        status_code=status_code,
        content_length=len(response.content),
        pii_findings=pii_findings,
        secret_findings=secret_findings,
        is_interesting=is_interesting,
    )


def _test_brute_values(
    session: requests.Session,
    base_url_no_path: str,
    full_path: str,
    endpoint: SpecEndpoint,
    rate_limiter: RateLimiter,
    include_all: bool,
    timeout: int = TIMEOUT,
) -> EndpointResult | None:
    """Brute-force parameter values to find the best response."""
    param_names: list[str] = []
    param_value_lists: list[list[Any]] = []

    for param in endpoint.parameters:
        if param.get("in") not in ("path", "query"):
            continue
        name = param.get("name", "")
        param_names.append(name)
        ptype, enum = _resolve_param_type_and_enum(param)
        param_value_lists.append(generate_parameter_values(ptype, enum))

    if not param_names:
        return test_single_endpoint(session, base_url_no_path, full_path, endpoint, rate_limiter, include_all, timeout)

    # Phase 1: Try combos from spec-provided values (respects enums and declared types)
    best: EndpointResult | None = None
    for combo in itertools_product(*param_value_lists):
        mapping = dict(zip(param_names, combo, strict=True))
        r = _test_with_mapping(
            session, base_url_no_path, full_path, endpoint, mapping, rate_limiter, include_all, timeout,
        )
        if r is not None and (best is None or r.content_length > best.content_length):
            best = r

    if best is not None:
        return best

    # Phase 2: Fallback — try generic type combos if spec values all failed
    for test_type in ("integer", "string", "boolean", "number"):
        fallback_values = [generate_parameter_values(test_type)] * len(param_names)
        first_combo = {n: vals[0] for n, vals in zip(param_names, fallback_values, strict=True)}

        result = _test_with_mapping(
            session, base_url_no_path, full_path, endpoint, first_combo, rate_limiter, include_all, timeout,
        )
        if result is None:
            continue

        best = result
        for combo in itertools_product(*fallback_values):
            mapping = dict(zip(param_names, combo, strict=True))
            r = _test_with_mapping(
                session, base_url_no_path, full_path, endpoint, mapping, rate_limiter, include_all, timeout,
            )
            if r is not None and r.content_length > best.content_length:
                best = r
        return best

    return best


def _test_with_mapping(
    session: requests.Session,
    base_url_no_path: str,
    full_path: str,
    endpoint: SpecEndpoint,
    value_mapping: dict[str, Any],
    rate_limiter: RateLimiter,
    include_all: bool,
    timeout: int = TIMEOUT,
) -> EndpointResult | None:
    """Send a GET request with a specific value mapping."""
    path = substitute_path_parameters(full_path, endpoint.parameters, value_mapping)
    qs = generate_query_string(endpoint.parameters, value_mapping)
    url = _build_full_url(base_url_no_path, path, qs)

    resp_result = http_get(session, url, rate_limiter, timeout)
    if isinstance(resp_result, IOFailure):
        return None

    response: requests.Response = resp_result.unwrap()._inner_value
    if response.status_code in (401, 403):
        return None

    content = response.text
    pii_findings, secret_findings, is_interesting = analyze_response(content)

    status_code = response.status_code
    if not (status_code == 200 or (include_all and status_code == 404)):
        is_interesting = False

    return EndpointResult(
        method="GET",
        url=url,
        path_template=endpoint.path_template,
        status_code=status_code,
        content_length=len(response.content),
        pii_findings=pii_findings,
        secret_findings=secret_findings,
        is_interesting=is_interesting,
    )


def test_all_endpoints(
    session: requests.Session,
    base_url: str,
    base_path: str,
    endpoints: list[SpecEndpoint],
    rate_limiter: RateLimiter,
    cancel_event: threading.Event,
    include_all: bool = False,
    brute: bool = False,
    timeout: int = TIMEOUT,
    tried_basepath_fallback: bool = False,
) -> list[EndpointResult]:
    """
    Test all GET endpoints sequentially, checking cancel_event between each.
    Includes basepath fallback heuristic (80%+ 404s → retry with '/').
    """
    if not base_path.startswith("/"):
        base_path = "/" + base_path
    if base_path.endswith("/") and base_path != "/":
        base_path = base_path.rstrip("/")
    # Avoid double-slash when base_path is "/" and path_template starts with "/"
    if base_path == "/":
        base_path = ""

    parsed = urlparse(base_url)
    base_url_no_path = f"{parsed.scheme}://{parsed.netloc}"

    results: list[EndpointResult] = []
    for endpoint in endpoints:
        if cancel_event.is_set():
            break

        full_path = base_path + endpoint.path_template
        if brute:
            result = _test_brute_values(
                session, base_url_no_path, full_path, endpoint,
                rate_limiter, include_all, timeout,
            )
        else:
            result = test_single_endpoint(
                session, base_url_no_path, full_path, endpoint,
                rate_limiter, include_all, timeout,
            )

        if result is not None:
            results.append(result)
            if result.status_code == 200:
                logger.debug("GET %s returned 200", result.url)

    # Basepath fallback: if 80%+ are 404 with same content_length, retry with no base path
    if not tried_basepath_fallback and results and base_path:
        num_404 = sum(1 for r in results if r.status_code == 404)
        if results and num_404 / len(results) > 0.8:
            lengths_404 = {r.content_length for r in results if r.status_code == 404}
            if len(lengths_404) == 1:
                logger.info("Basepath fallback triggered. Retesting with '/'.")
                return test_all_endpoints(
                    session, base_url, "/", endpoints, rate_limiter,
                    cancel_event, include_all, brute, timeout,
                    tried_basepath_fallback=True,
                )

    return results
