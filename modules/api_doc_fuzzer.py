# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Discover Swagger / OpenAPI / GraphQL schema artifacts, parse them, and fuzz
operations for IDOR (numeric id mutations) and light SQL-injection probes.

Authorized testing only.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlencode, urljoin, urlparse

import aiohttp

from .evasion import EvasionProfile, build_browser_headers, friendly_network_error
from .idor_scanner import IDORScanner
from .scanner_engine import http_client_timeout

PlanCallback = Callable[[int], None]
ProgressCallback = Callable[[], None]

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

_DISCOVERY_PATHS: tuple[str, ...] = (
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json",
    "/swagger-resources",
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
    "/graphiql",
)

_SQL_ERROR_SNIPPETS = re.compile(
    r"(sql syntax|syntax error|mysql|postgresql|ora-\d|sqlite|"
    r"mssql|odbc driver|unclosed quotation|quoted string not properly)",
    re.I,
)

_SQL_TIME_PAYLOAD = "' AND (SELECT 1 FROM (SELECT SLEEP(2))a)-- -"

_GQL_INTROSPECTION_BODY: dict[str, Any] = {
    "query": (
        "query Introspection{__schema{queryType{name}"
        " types{name kind}}}"
    )
}


def _load_doc_text(raw: bytes, content_type: str) -> dict[str, Any] | None:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return None
    if text.startswith("{") or text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    ct = (content_type or "").lower()
    if "yaml" in ct or text.startswith("openapi:") or text.startswith("swagger:"):
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else None
        except Exception:
            return None
    try:
        import yaml  # type: ignore[import-untyped]

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _origin_from_target(target_url: str) -> str:
    raw = target_url.strip()
    if "://" not in raw:
        raw = f"https://{raw}"
    p = urlparse(raw)
    scheme = p.scheme or "https"
    netloc = p.netloc or (p.path.split("/")[0] if p.path else "")
    if not netloc and "://" not in target_url.strip():
        netloc = target_url.strip().split("/")[0]
    return f"{scheme}://{netloc}".rstrip("/")


def _resolve_servers_swagger2(doc: dict[str, Any], origin: str) -> str:
    schemes = doc.get("schemes") or ["https"]
    host = (doc.get("host") or urlparse(origin).netloc or "").strip()
    if not host:
        host = urlparse(origin).netloc
    base_path = doc.get("basePath") or "/"
    if not str(base_path).startswith("/"):
        base_path = "/" + str(base_path)
    return urljoin(f"{schemes[0]}://{host}", base_path).rstrip("/")


def _resolve_servers_oas3(doc: dict[str, Any], origin: str) -> str:
    servers = doc.get("servers") or [{"url": "/"}]
    surl = str(servers[0].get("url", "/")).strip()
    if surl.startswith("/"):
        return (origin.rstrip("/") + surl).rstrip("/")
    return surl.rstrip("/")


@dataclass
class _ResolvedParam:
    name: str
    where: str
    schema: dict[str, Any]
    required: bool = False

    def is_integer_like(self) -> bool:
        t = (self.schema.get("type") or "").lower()
        if t in ("integer", "number", "int", "long"):
            return True
        return bool(IDORScanner.ID_PARAM_PATTERN.match(self.name))

    def is_string_like(self) -> bool:
        t = (self.schema.get("type") or "").lower()
        return t in ("string", "str", "") or t not in ("integer", "number", "boolean", "array", "object")


@dataclass
class _Operation:
    method: str
    path_template: str
    operation_id: str
    params: list[_ResolvedParam] = field(default_factory=list)
    request_body_json: bool = False
    body_schema: dict[str, Any] = field(default_factory=dict)


def _schema_from_param(p: dict[str, Any]) -> dict[str, Any]:
    sch = p.get("schema") or p
    if isinstance(sch, dict):
        return sch
    return {}


def _collect_operations(doc: dict[str, Any], origin: str) -> tuple[str, list[_Operation], str]:
    """Return (base_url, operations, flavor)."""
    if "swagger" in doc and str(doc.get("swagger", "")).startswith("2"):
        base = _resolve_servers_swagger2(doc, origin)
        flavor = "swagger2"
    elif "openapi" in doc:
        base = _resolve_servers_oas3(doc, origin)
        flavor = "openapi3"
    else:
        return "", [], "unknown"

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return base, [], flavor

    ops: list[_Operation] = []
    for path_template, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        common_params: list[dict[str, Any]] = list(path_item.get("parameters") or [])
        for method in ("get", "post", "put", "patch", "delete", "head"):
            op_block = path_item.get(method)
            if not isinstance(op_block, dict):
                continue
            plist: list[_ResolvedParam] = []
            for p in common_params + list(op_block.get("parameters") or []):
                if not isinstance(p, dict):
                    continue
                if "$ref" in p:
                    continue
                name = str(p.get("name", ""))
                where = str(p.get("in", "query"))
                if not name:
                    continue
                plist.append(
                    _ResolvedParam(
                        name=name,
                        where=where,
                        schema=_schema_from_param(p),
                        required=bool(p.get("required")),
                    )
                )
            rb = op_block.get("requestBody") or {}
            content = rb.get("content") if isinstance(rb, dict) else {}
            json_body = False
            body_sch: dict[str, Any] = {}
            if isinstance(content, dict):
                app_json = content.get("application/json")
                if isinstance(app_json, dict):
                    json_body = True
                    body_sch = app_json.get("schema") or {}
            op_id = str(op_block.get("operationId") or f"{method}_{path_template}")
            ops.append(
                _Operation(
                    method=method,
                    path_template=str(path_template),
                    operation_id=op_id[:120],
                    params=plist,
                    request_body_json=json_body,
                    body_schema=body_sch if isinstance(body_sch, dict) else {},
                )
            )
    return base, ops, flavor


def _default_value_for_param(rp: _ResolvedParam, *, id_seed: int) -> str:
    if rp.is_integer_like():
        return str(id_seed)
    if (rp.schema.get("type") or "").lower() == "boolean":
        return "true"
    return "test"


def _build_url(
    base: str,
    op: _Operation,
    *,
    id_param: str | None,
    id_value: int,
) -> str | None:
    path = op.path_template
    query: dict[str, str] = {}
    for rp in op.params:
        if rp.where == "path":
            if rp.is_integer_like():
                pv = str(id_value if id_param and rp.name == id_param else 1)
            else:
                pv = _default_value_for_param(rp, id_seed=1)
            path = path.replace("{" + rp.name + "}", pv)
        elif rp.where == "query":
            if rp.is_integer_like():
                qv = str(id_value if id_param and rp.name == id_param else 1)
            else:
                qv = _default_value_for_param(rp, id_seed=1)
            query[rp.name] = qv
    if "{" in path:
        return None
    url = (
        base.rstrip("/") + "/" + path.lstrip("/")
        if not path.startswith("http")
        else path
    )
    if query:
        url = url + "?" + urlencode(query)
    return url


def _pick_id_param(op: _Operation) -> str | None:
    for rp in op.params:
        if rp.where in ("path", "query") and rp.is_integer_like():
            return rp.name
    return None


def _pick_string_query_param(op: _Operation) -> str | None:
    if op.method != "get":
        return None
    for rp in op.params:
        if rp.where == "query" and rp.is_string_like() and not rp.is_integer_like():
            return rp.name
    return None


class APISchemaFuzzer:
    """Deep API documentation harvest + structured fuzzing."""

    def __init__(
        self,
        *,
        max_operations: int = 32,
        max_post_inject: int = 8,
        sql_time_threshold: float = 2.15,
        extra_headers: dict[str, str] | None = None,
        evasion: EvasionProfile | None = None,
    ) -> None:
        self._max_ops = max_operations
        self._max_post = max_post_inject
        self._sql_threshold = sql_time_threshold
        self._extra = dict(extra_headers or {})
        self._evasion = evasion or EvasionProfile()
        self._timeout = http_client_timeout()
        self._idor = IDORScanner(
            extra_headers=self._extra,
            evasion=self._evasion,
            concurrency=6,
        )

    async def _fetch_bytes(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        referer: str,
        method: str = "GET",
        json_body: Any | None = None,
    ) -> tuple[int, bytes, str]:
        await self._evasion.apply_jitter()
        headers = build_browser_headers(
            referer=referer,
            extra=self._extra,
            accept="application/json, text/plain, */*",
            evasion=self._evasion,
        )
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        try:
            req_kw: dict[str, Any] = {"headers": headers, "allow_redirects": True}
            if json_body is not None:
                req_kw["json"] = json_body
            async with session.request(method, url, **req_kw) as resp:
                raw = await resp.read()
                return resp.status, raw[:1_500_000], str(resp.content_type or "")
        except (aiohttp.ClientError, TimeoutError, OSError):
            return -1, b"", ""

    async def _fetch_text_timed(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        referer: str,
        method: str = "GET",
        json_body: Any | None = None,
    ) -> tuple[int, str, float]:
        t0 = time.monotonic()
        st, raw, _ = await self._fetch_bytes(
            session, url, referer=referer, method=method, json_body=json_body
        )
        elapsed = time.monotonic() - t0
        return st, raw.decode("utf-8", errors="replace"), elapsed

    async def scan(
        self,
        target_url: str,
        on_plan: PlanCallback | None = None,
        on_advance: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        def adv() -> None:
            if on_advance:
                try:
                    on_advance()
                except Exception:
                    pass

        origin = _origin_from_target(target_url)
        referer = target_url if "://" in target_url else f"https://{target_url}"

        try:
            connector = self._evasion.aiohttp_connector(ssl=True, limit=24)
        except RuntimeError:
            raise

        try:
            async with aiohttp.ClientSession(
                timeout=self._timeout, connector=connector, trust_env=False
            ) as session:
                return await self._scan_session(
                    session,
                    origin,
                    referer,
                    on_plan,
                    adv,
                )
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise RuntimeError(friendly_network_error(exc)) from exc

    async def _scan_session(
        self,
        session: aiohttp.ClientSession,
        origin: str,
        referer: str,
        on_plan: PlanCallback | None,
        adv: Callable[[], None],
    ) -> dict[str, Any]:
        discovered: list[dict[str, Any]] = []
        idor_rows: list[dict[str, Any]] = []
        injection_rows: list[dict[str, Any]] = []
        graphql_rows: list[dict[str, Any]] = []

        to_check = [urljoin(origin + "/", p.lstrip("/")) for p in _DISCOVERY_PATHS]
        plan_extra = len(to_check) + self._max_ops * 8
        if on_plan:
            try:
                on_plan(max(8, plan_extra))
            except Exception:
                pass

        openapi_ops: list[tuple[str, _Operation, str, str]] = []
        op_dedupe: set[tuple[str, str, str]] = set()

        for durl in to_check:
            st, raw, ctype = await self._fetch_bytes(session, durl, referer=referer)
            adv()
            if st != 200 or not raw:
                continue
            low = durl.lower()
            if any(x in low for x in ("/graphql", "/graphiql", "/query")):
                st2, body, _ = await self._fetch_text_timed(
                    session,
                    durl.split("?")[0],
                    referer=referer,
                    method="POST",
                    json_body=_GQL_INTROSPECTION_BODY,
                )
                adv()
                if st2 == 200:
                    try:
                        gj = json.loads(body)
                    except json.JSONDecodeError:
                        gj = {}
                    types_n = 0
                    if isinstance(gj.get("data"), dict):
                        schema = gj["data"].get("__schema") or {}
                        types = schema.get("types") or []
                        types_n = len(types) if isinstance(types, list) else 0
                    if types_n > 0:
                        graphql_rows.append(
                            {
                                "type": "graphql_introspection",
                                "severity": SEVERITY_HIGH,
                                "url": durl,
                                "note": (
                                    f"GraphQL introspection returned {types_n} types — "
                                    "schema may be fully enumerable."
                                ),
                            }
                        )
                continue

            doc = _load_doc_text(raw, ctype)
            if not doc:
                continue
            if "swagger" not in doc and "openapi" not in doc:
                continue
            base, ops, flavor = _collect_operations(doc, origin)
            if not ops:
                continue
            discovered.append(
                {
                    "type": "api_spec",
                    "severity": SEVERITY_MEDIUM,
                    "url": durl,
                    "note": f"{flavor} — {len(ops)} operations parsed",
                    "flavor": flavor,
                    "operation_count": len(ops),
                }
            )
            for op in ops:
                key = (op.method.lower(), op.path_template, op.operation_id)
                if key in op_dedupe:
                    continue
                op_dedupe.add(key)
                openapi_ops.append((base, op, flavor, durl))
            if len(openapi_ops) >= 96:
                break

        if not openapi_ops and not graphql_rows:
            adv()
            return {
                "discovered": discovered,
                "idor": idor_rows,
                "injection": injection_rows,
                "graphql": graphql_rows,
            }

        openapi_ops = openapi_ops[: self._max_ops * 2]
        post_budget = self._max_post
        for base, op, flavor, doc_url in openapi_ops:
            id_param = _pick_id_param(op)
            if id_param and op.method == "get":
                seed = 100
                base_url = _build_url(base, op, id_param=id_param, id_value=seed)
                if not base_url:
                    adv()
                    continue
                baseline = await self._idor._fetch(session, base_url, referer=referer)
                adv()
                if baseline[0] is None:
                    continue
                for delta in IDORScanner.TEST_DELTAS:
                    new_val = seed + delta
                    if new_val <= 0:
                        continue
                    mu = _build_url(base, op, id_param=id_param, id_value=new_val)
                    if not mu:
                        continue
                    mutated = await self._idor._fetch(session, mu, referer=referer)
                    adv()
                    cl = self._idor._classify(baseline, mutated)
                    if cl:
                        idor_rows.append(
                            {
                                "severity": cl["severity"],
                                "kind": f"api_{op.method}",
                                "param": id_param,
                                "base_id": seed,
                                "test_id": new_val,
                                "status": cl["status"],
                                "similarity": cl["similarity"],
                                "url": mu,
                                "note": cl["note"]
                                + f" [schema:{flavor} op={op.operation_id}]",
                                "operation_id": op.operation_id,
                                "doc_url": doc_url,
                            }
                        )

            sq_param = _pick_string_query_param(op)
            if sq_param and op.method == "get":
                bu = _build_url_for_sqli(base, op, id_param, sq_param)
                if bu:
                    await self._fetch_text_timed(session, bu[0], referer=referer)
                    adv()
                    st1, body1, el1 = await self._fetch_text_timed(
                        session, bu[1], referer=referer
                    )
                    adv()
                    if st1 == 200 and _SQL_ERROR_SNIPPETS.search(body1):
                        injection_rows.append(
                            {
                                "type": "api_sqli_error",
                                "severity": SEVERITY_HIGH,
                                "method": "GET",
                                "param": sq_param,
                                "url": bu[1][:800],
                                "note": "SQL/database error pattern in response body",
                                "operation_id": op.operation_id,
                            }
                        )
                    elif el1 >= self._sql_threshold and st1 == 200:
                        injection_rows.append(
                            {
                                "type": "api_sqli_time",
                                "severity": SEVERITY_HIGH,
                                "method": "GET",
                                "param": sq_param,
                                "url": bu[1][:800],
                                "note": (
                                    f"Delayed response ~{el1:.1f}s "
                                    "(possible time-based SQLi)"
                                ),
                                "operation_id": op.operation_id,
                            }
                        )

            if (
                op.method in ("post", "put", "patch")
                and op.request_body_json
                and post_budget > 0
            ):
                post_budget -= 1
                sample_body, inj_body = _sample_json_bodies(op.body_schema)
                if not sample_body:
                    continue
                full = _operation_url_no_unknown(base, op, id_param=id_param)
                if not full:
                    continue
                await self._fetch_text_timed(
                    session,
                    full,
                    referer=referer,
                    method=op.method.upper(),
                    json_body=sample_body,
                )
                adv()
                st1, _, el1 = await self._fetch_text_timed(
                    session,
                    full,
                    referer=referer,
                    method=op.method.upper(),
                    json_body=inj_body,
                )
                adv()
                if el1 >= self._sql_threshold and st1 in (200, 201, 400, 500):
                    injection_rows.append(
                        {
                            "type": "api_sqli_time",
                            "severity": SEVERITY_HIGH,
                            "method": op.method.upper(),
                            "param": "(json body)",
                            "url": full[:800],
                            "note": (
                                f"JSON body with SLEEP payload delayed ~{el1:.1f}s "
                                f"[{op.operation_id}]"
                            ),
                            "operation_id": op.operation_id,
                        }
                    )

        seen: set[tuple[Any, ...]] = set()
        dedup_idor: list[dict[str, Any]] = []
        for r in idor_rows:
            k = (r.get("url"), r.get("test_id"), r.get("severity"))
            if k in seen:
                continue
            seen.add(k)
            dedup_idor.append(r)

        return {
            "discovered": discovered,
            "idor": dedup_idor,
            "injection": injection_rows,
            "graphql": graphql_rows,
        }


def _build_url_for_sqli(
    base: str,
    op: _Operation,
    id_param: str | None,
    sq_param: str,
) -> tuple[str, str] | None:
    path = op.path_template
    query: dict[str, str] = {}
    for rp in op.params:
        if rp.name == sq_param and rp.where == "query":
            continue
        if rp.where == "path":
            if rp.is_integer_like():
                pv = str(100 if (id_param and rp.name == id_param) else 1)
            else:
                pv = _default_value_for_param(rp, id_seed=1)
            path = path.replace("{" + rp.name + "}", pv)
        elif rp.where == "query" and rp.name != sq_param:
            if rp.is_integer_like():
                query[rp.name] = str(100 if (id_param and rp.name == id_param) else 1)
            else:
                query[rp.name] = _default_value_for_param(rp, id_seed=1)
    if "{" in path:
        return None
    url0 = base.rstrip("/") + "/" + path.lstrip("/")
    q0 = dict(query)
    q0[sq_param] = "a"
    q1 = dict(query)
    q1[sq_param] = _SQL_TIME_PAYLOAD
    return (
        url0 + "?" + urlencode(q0),
        url0 + "?" + urlencode(q1),
    )


def _operation_url_no_unknown(
    base: str,
    op: _Operation,
    *,
    id_param: str | None,
) -> str | None:
    return _build_url(base, op, id_param=id_param, id_value=100)


def _sample_json_bodies(
    schema: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    if schema.get("type") != "object" or not isinstance(schema.get("properties"), dict):
        return None, None
    props = schema["properties"]
    sample: dict[str, Any] = {}
    inj_field: str | None = None
    for key, sub in props.items():
        if not isinstance(sub, dict):
            continue
        t = (sub.get("type") or "").lower()
        if t == "integer":
            sample[key] = 1
        elif t == "boolean":
            sample[key] = True
        elif t == "string" and inj_field is None:
            sample[key] = "test"
            inj_field = key
        else:
            sample[key] = None
    if inj_field is None:
        return None, None
    inj = dict(sample)
    inj[inj_field] = f"1' AND (SELECT 1 FROM (SELECT SLEEP(2))a) AND '1'='1"
    return sample, inj
