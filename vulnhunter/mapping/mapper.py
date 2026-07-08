"""Breadth-first mapping built exclusively on the safe HTTP transport."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import UTC, datetime

from bs4 import BeautifulSoup

from vulnhunter.exceptions import ScopeValidationError
from vulnhunter.mapping.models import MappedPage, MapperPolicy, MappingResult
from vulnhunter.observations.analyzers import analyze_response
from vulnhunter.scanner.client import SafeHttpClient
from vulnhunter.scope.guard import validate_scoped_url
from vulnhunter.scope.models import ApprovedTarget, ScopedUrl
from vulnhunter.scope.validator import Resolver, system_resolver
from vulnhunter.security import redact_text, redact_url

_IGNORED_LINK_PREFIXES = ("#", "mailto:", "tel:", "javascript:", "data:")
_HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")


def _is_html(content_type: str) -> bool:
    return any(value in content_type.lower() for value in _HTML_CONTENT_TYPES)


def _extract_title(body: bytes) -> str | None:
    soup = BeautifulSoup(body, "html.parser")

    if soup.title is None:
        return None

    title = soup.title.get_text(" ", strip=True)
    return redact_text(title[:200]) if title else None


def _extract_links(body: bytes, maximum_links: int) -> Iterable[str]:
    soup = BeautifulSoup(body, "html.parser")
    links_seen = 0

    for element in soup.find_all(["a", "area"], href=True):
        href = str(element.get("href", "")).strip()

        if not href or href.lower().startswith(_IGNORED_LINK_PREFIXES):
            continue

        yield href
        links_seen += 1

        if links_seen >= maximum_links:
            return


class SiteMapper:
    """Map in-scope HTML links without issuing active security probes."""

    def __init__(
        self,
        target: ApprovedTarget,
        client: SafeHttpClient,
        *,
        policy: MapperPolicy | None = None,
        resolver: Resolver = system_resolver,
    ) -> None:
        self._target = target
        self._client = client
        self._policy = policy or MapperPolicy()
        self._resolver = resolver

    async def map(self) -> MappingResult:
        """Map the approved target using a bounded breadth-first traversal."""
        started_at = datetime.now(UTC)
        starting_url = validate_scoped_url(
            self._target,
            self._target.normalized_url,
            resolver=self._resolver,
        )

        starting_key = redact_url(starting_url.url)
        queue: deque[tuple[ScopedUrl, int]] = deque([(starting_url, 0)])
        queued_keys = {starting_key}
        visited_keys: set[str] = set()
        pages: list[MappedPage] = []
        observations = []
        rejected_links = 0

        while queue and len(pages) < self._policy.maximum_pages:
            current_url, depth = queue.popleft()
            current_key = redact_url(current_url.url)

            if current_key in visited_keys:
                continue

            response = await self._client.request("GET", current_url)
            final_key = redact_url(response.final_url.url)

            visited_keys.add(current_key)

            if final_key in visited_keys and final_key != current_key:
                continue

            visited_keys.add(final_key)
            content_type = response.headers.get("content-type", "")
            discovered_on_page = 0

            if _is_html(content_type) and depth < self._policy.maximum_depth:
                for candidate in _extract_links(
                    response.body,
                    self._policy.maximum_links_per_page,
                ):
                    try:
                        scoped_candidate = validate_scoped_url(
                            self._target,
                            candidate,
                            base_url=response.final_url.url,
                            resolver=self._resolver,
                        )
                    except ScopeValidationError:
                        rejected_links += 1
                        continue

                    discovered_on_page += 1
                    candidate_key = redact_url(scoped_candidate.url)

                    if candidate_key not in visited_keys and candidate_key not in queued_keys:
                        queue.append((scoped_candidate, depth + 1))
                        queued_keys.add(candidate_key)

            pages.append(
                MappedPage(
                    url=final_key,
                    depth=depth,
                    status_code=response.status_code,
                    content_type=redact_text(content_type[:500]),
                    response_bytes=len(response.body),
                    elapsed_ms=response.elapsed_ms,
                    title=_extract_title(response.body) if _is_html(content_type) else None,
                    links_discovered=discovered_on_page,
                )
            )
            observations.extend(analyze_response(response))

        return MappingResult(
            target_url=redact_url(self._target.normalized_url),
            started_at=started_at,
            completed_at=datetime.now(UTC),
            pages=tuple(pages),
            observations=tuple(observations),
            discovered_urls=len(queued_keys),
            rejected_links=rejected_links,
        )
