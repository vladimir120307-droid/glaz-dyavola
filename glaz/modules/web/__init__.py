from glaz.modules.web.attack_surface import (
    GRAPHQL_PATHS,
    SWAGGER_PATHS,
    discover_web_surface,
    extract_endpoints_from_js,
    fetch_security_headers,
)

__all__ = [
    "GRAPHQL_PATHS", "SWAGGER_PATHS",
    "discover_web_surface", "extract_endpoints_from_js", "fetch_security_headers",
]
