# Developed by Channa Sandeepa | OmniScan-AI v2.0 | Copyright 2026
"""Tech-stack detection and context-aware path wordlists for reconnaissance."""

from __future__ import annotations

from typing import Iterable

# Match ``path_bruter`` tiers (avoid circular import).
_SEV_H = "High"
_SEV_M = "Medium"
_SEV_L = "Low"

# ---------------------------------------------------------------------------
# Tech signals (HTML body + response headers)
# ---------------------------------------------------------------------------


def detect_tech_stack(html: str, response_headers: dict[str, str] | None = None) -> set[str]:
    """Return coarse tags: php, wordpress, aspnet, java, python, node, ruby, nextjs, spa."""
    tags: set[str] = set()
    text = (html or "").lower()
    hdr = ""
    if response_headers:
        hdr = " ".join(f"{k} {v}" for k, v in response_headers.items()).lower()
    blob = text + " " + hdr

    if any(
        x in blob
        for x in (
            "x-powered-by: php",
            "php/",
            ".php",
            "<?php",
            "laravel",
            "symfony",
        )
    ) or "php" in hdr:
        tags.add("php")

    if any(x in text for x in ("wp-content", "wp-includes", "wordpress", "/wp-json/")):
        tags.add("wordpress")

    if any(
        x in blob
        for x in (
            "x-aspnet-version",
            "x-powered-by: asp.net",
            "__viewstate",
            "iis/",
            ".aspx",
        )
    ):
        tags.add("aspnet")

    if any(
        x in blob
        for x in (
            "apache-coyote",
            "x-powered-by: servlet",
            "jsessionid",
            "spring",
            "struts",
            "tomcat",
            "weblogic",
            "glassfish",
            "wildfly",
        )
    ):
        tags.add("java")

    if any(
        x in blob
        for x in (
            "gunicorn",
            "uvicorn",
            "werkzeug",
            "django",
            "flask",
            "python/",
        )
    ):
        tags.add("python")

    if any(
        x in blob
        for x in (
            "express",
            "x-powered-by: node",
            "next.js",
            "_next/",
            "nuxt",
            "webpack",
            "vite",
        )
    ):
        tags.add("node")

    if any(x in blob for x in ("rails", "rack", "phusion passenger", "_rails")):
        tags.add("ruby")

    if "_next/" in text or "__next" in text or "next/font" in text:
        tags.add("nextjs")

    if any(x in text for x in ("react-dom", "react-router", "__react")):
        tags.add("spa_react")

    return tags


def smart_paths_for_stack(tags: Iterable[str]) -> list[tuple[str, str]]:
    """Return ``(relative_path, default_severity)`` extensions for detected stacks."""
    t = set(tags)
    out: list[tuple[str, str]] = []

    def add(paths: tuple[str, ...], sev: str) -> None:
        for p in paths:
            out.append((p, sev))

    if "php" in t or "wordpress" in t:
        add(
            (
                "config.php",
                "configuration.php",
                "settings.php",
                "db.php",
                "database.php",
                "includes/config.php",
                "lib/config.php",
                "vendor/autoload.php",
                "composer.json",
                "composer.lock",
            ),
            _SEV_H,
        )
        add(("phpinfo.php", "test.php", "info.php"), _SEV_M)

    if "wordpress" in t:
        add(
            (
                "wp-config.php",
                "wp-config.php.bak",
                "wp-config.txt",
                "readme.html",
                "license.txt",
            ),
            _SEV_H,
        )

    if "aspnet" in t:
        add(
            (
                "web.config",
                "web.config.bak",
                "bin/",
                "App_Data/",
                "elmah.axd",
                "trace.axd",
            ),
            _SEV_H,
        )

    if "java" in t:
        add(
            (
                "WEB-INF/web.xml",
                "META-INF/MANIFEST.MF",
                "actuator/",
                "manager/html",
                "host-manager/html",
            ),
            _SEV_H,
        )

    if "python" in t:
        add(
            (
                "settings.py",
                "local_settings.py",
                "wsgi.py",
                "asgi.py",
                "requirements.txt",
                "Pipfile",
                "pyproject.toml",
            ),
            _SEV_H,
        )

    if "node" in t or "nextjs" in t or "spa_react" in t:
        add(
            (
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "pnpm-lock.yaml",
                ".next/",
                "next.config.js",
                "next.config.mjs",
                "server.js",
                "app.js",
                "nuxt.config.js",
            ),
            _SEV_M,
        )

    if "ruby" in t:
        add(
            (
                "config/database.yml",
                "config/secrets.yml",
                "Gemfile",
                "Gemfile.lock",
            ),
            _SEV_H,
        )

    # Dedupe preserving order
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for path, sev in out:
        key = (path, sev)
        if path in seen:
            continue
        seen.add(path)
        unique.append((path, sev))
    return unique


# Suffixes probed under each *discovered* directory prefix (recursive bruting)
RECURSIVE_DIR_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".env", _SEV_H),
    (".env.local", _SEV_H),
    ("config.php", _SEV_H),
    ("config.json", _SEV_M),
    ("settings.json", _SEV_M),
    ("web.config", _SEV_H),
    ("package.json", _SEV_L),
    (".git/config", _SEV_H),
    ("composer.json", _SEV_L),
    ("backup.sql", _SEV_H),
    ("dump.sql", _SEV_H),
    ("db.sqlite", _SEV_H),
    ("index.php", _SEV_L),
    ("login", _SEV_L),
    ("admin", _SEV_L),
    ("api/", _SEV_L),
    ("graphql", _SEV_L),
    ("swagger.json", _SEV_L),
    ("openapi.json", _SEV_L),
)
