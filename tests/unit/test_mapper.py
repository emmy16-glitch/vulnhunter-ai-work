from collections.abc import Iterable

import httpx
import pytest

from vulnhunter.mapping import MapperPolicy, SiteMapper
from vulnhunter.scanner import HttpClientPolicy, SafeHttpClient
from vulnhunter.scope import validate_target


def resolver(_: str) -> Iterable[str]:
    return ("10.0.0.5",)


@pytest.mark.asyncio
async def test_mapper_visits_only_in_scope_html_links():
    target = validate_target("http://lab.internal:8000/app/", resolver=resolver)
    requested = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request.url.path)
        if request.url.path == "/app/":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=(
                    b'<a href="/app/about">About</a>'
                    b'<a href="/app/about">Duplicate</a>'
                    b'<a href="/admin">Outside path</a>'
                    b'<a href="http://other.internal:8000/app/">Other host</a>'
                    b'<a href="mailto:test@example.com">Mail</a>'
                ),
            )
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=b"About")

    async with SafeHttpClient(
        target,
        policy=HttpClientPolicy(minimum_request_delay_seconds=0),
        resolver=resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await SiteMapper(
            target,
            client,
            policy=MapperPolicy(maximum_pages=10, maximum_depth=2),
            resolver=resolver,
        ).map()

    assert requested == ["/app/", "/app/about"]
    assert len(result.pages) == 2
    assert result.discovered_urls == 2
    assert result.rejected_links == 2
    assert result.observations


@pytest.mark.asyncio
async def test_mapper_respects_depth_limit():
    target = validate_target("http://lab.internal:8000/app/", resolver=resolver)

    async def handler(request: httpx.Request) -> httpx.Response:
        next_link = {
            "/app/": "/app/one",
            "/app/one": "/app/two",
        }.get(request.url.path)
        body = f'<a href="{next_link}">Next</a>'.encode() if next_link else b"Done"
        return httpx.Response(200, headers={"Content-Type": "text/html"}, content=body)

    async with SafeHttpClient(
        target,
        policy=HttpClientPolicy(minimum_request_delay_seconds=0),
        resolver=resolver,
        transport=httpx.MockTransport(handler),
    ) as client:
        result = await SiteMapper(
            target,
            client,
            policy=MapperPolicy(maximum_pages=10, maximum_depth=1),
            resolver=resolver,
        ).map()

    assert [page.url for page in result.pages] == [
        "http://lab.internal:8000/app/",
        "http://lab.internal:8000/app/one",
    ]
