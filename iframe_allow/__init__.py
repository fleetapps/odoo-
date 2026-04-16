"""
post_load entry point for the iframe_allow addon.

WHY post_load and not models/:
  Odoo imports Python files from a module's models/ directory at server startup
  regardless of whether the addon is installed. A patch placed there can fire
  multiple times, before http.Application is fully initialised, or even when the
  addon is explicitly uninstalled. post_load is called exactly once, at the correct
  point in the server lifecycle (after the HTTP stack is ready), and only when the
  addon is active.  Reference: https://www.odoo.com/documentation/17.0/reference/module.html

  The manifest declares:  'post_load': 'apply_iframe_patch'
  Odoo resolves that to this function at the module (package) level.
"""
import logging
import os

from . import controllers  # noqa: F401 — register /vibe_iframe/* routes

_logger = logging.getLogger(__name__)


def _collapse_csp_values(csp_values, frame_ancestors_directive):
    """Merge CSP header values into a single policy string.

    Browsers intersect multiple Content-Security-Policy headers (strictest wins for
    each directive). Odoo's /web/login sends ``frame-ancestors 'self'`` while this
    addon previously appended a second CSP; together they forbid any cross-origin
    parent (see MDN: Multiple content security policies). We strip every
    frame-ancestors clause from existing policies, drop duplicate directive names,
    then append exactly one frame-ancestors directive listing our allowlist.
    """
    clauses = []
    seen = set()
    for csp in csp_values:
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            name = part.split(None, 1)[0].lower()
            if name == "frame-ancestors":
                continue
            if name not in seen:
                seen.add(name)
                clauses.append(part)
    clauses.append(frame_ancestors_directive)
    return "; ".join(clauses)


def apply_iframe_patch():
    """
    Remove X-Frame-Options and emit a single Content-Security-Policy whose
    frame-ancestors allow the builder origins in ALLOWED_IFRAME_ORIGINS.

    Required env var (set in Render → Environment on the Odoo service):
        ALLOWED_IFRAME_ORIGINS  Space-separated list of allowed parent origins.
        Example: "https://app.yourdomain.com https://vibe-odoo-xxx.onrender.com"
        If unset, embedding is disabled via frame-ancestors 'none'.

    WHY CSP only:
        X-Frame-Options cannot list multiple third-party origins. CSP frame-ancestors
        is the supported mechanism (MDN). We remove X-Frame-Options so it cannot
        conflict with CSP on responses that set both (e.g. /web sets XFO:DENY).
    """
    from odoo import http  # import inside function — http is guaranteed ready here

    raw = os.environ.get("ALLOWED_IFRAME_ORIGINS", "").strip()
    if raw:
        fa_directive = f"frame-ancestors 'self' {raw}"
    else:
        fa_directive = "frame-ancestors 'none'"

    _logger.info("iframe_allow: post_load active — %s", fa_directive)

    original_dispatch = http.Application.__call__

    def patched_dispatch(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            hdrs = list(headers)
            filtered = [(k, v) for k, v in hdrs if k.lower() != "x-frame-options"]
            csp_values = [v for k, v in filtered if k.lower() == "content-security-policy"]
            rest = [(k, v) for k, v in filtered if k.lower() != "content-security-policy"]
            if csp_values:
                merged = _collapse_csp_values(csp_values, fa_directive)
            else:
                merged = fa_directive
            rest.append(("Content-Security-Policy", merged))
            return start_response(status, rest, exc_info)

        return original_dispatch(self, environ, custom_start_response)

    http.Application.__call__ = patched_dispatch
