# -*- coding: utf-8 -*-
"""Trusted auto-login controller for the vibe-odoo builder "Live View" flow.

Design
------
The builder opens the target Odoo app in a **new browser tab** (top-level
navigation, NOT an iframe). To avoid exposing the sandbox password as a query
parameter in the URL (browser history, server logs, referrer leakage) the
gateway serves a tiny HTML trampoline page at ``/api/odoo/auto-login/:appId``
that contains an auto-submitting ``<form method="POST">`` whose action is this
controller. The POST body travels over HTTPS, is not stored in history, and the
response immediately 303s to the target app URL with a fresh ``session_id``
cookie pinned to the Odoo origin.

Why a custom controller (not /web/login or /web/session/authenticate)
---------------------------------------------------------------------
* ``/web/login`` — ``csrf=True`` on Odoo 19; external form POST fails with 403
  unless we GET /web/login first to scrape csrf_token. Brittle + extra RTT.
* ``/web/session/authenticate`` — ``type='jsonrpc'`` on Odoo 19; form POST is
  rejected as wrong Content-Type and it returns JSON, not a redirect.
* This controller — ``csrf=False``, accepts form POST, authenticates, sets the
  ``session_id`` cookie, redirects. Gated by ``ALLOWED_IFRAME_ORIGINS``
  (Origin/Referer allow-list).

Reliability notes
-----------------
This route dispatches via ``_serve_nodb`` (``auth="none"`` + typically no
session cookie yet), which means:

* ``request.db`` is ``None`` and ``request.env`` is ``None`` for the duration
  of the call.
* We must open our own ``Registry(db).cursor()`` and build an
  ``api.Environment`` to hand to ``request.session.authenticate(env, cred)``.
  Reference: ``odoo/http.py::Session.authenticate`` (Odoo 19, L1178).
* We cannot rely on ``request.redirect()`` — it falls through to
  ``werkzeug.utils.redirect`` when ``request.db`` is unset, but it also uses
  Odoo's custom ``Response`` class whose ``set_cookie`` touches
  ``request.env['ir.http']._is_allowed_cookie`` (L1551). Predictability beats
  cleverness here: we build the ``werkzeug`` response ourselves and set the
  cookie explicitly while the authenticating env is still live.
* ``Dispatcher.post_dispatch`` (L2385) calls ``request._save_session()`` with
  ``env=None`` after the controller returns. That's safe because we've
  already ``rotate``d the session with the correct env, so ``should_rotate``
  is ``False`` and no further env-requiring work runs.

Redirect target hardening
-------------------------
The ``redirect`` form field is normalised to a **same-origin relative path**
and validated against a small allow-list of Odoo URL prefixes (``/odoo``,
``/web``, ``/my``). Anything else (empty, protocol-relative, cross-origin,
unknown path) falls back to ``/odoo`` — the webclient home — so the user
never lands on a 404 even if the stored app URL is stale.
"""
import logging
import os
from contextlib import ExitStack
from urllib.parse import urlparse

import werkzeug.utils

import odoo
import odoo.modules.registry
from odoo import api, http
from odoo.exceptions import AccessDenied
from odoo.http import get_session_max_inactivity, request

_logger = logging.getLogger(__name__)

# ── Redirect allow-list ──────────────────────────────────────────────────────
# Keep this minimal. Everything outside these prefixes falls back to /odoo.
# (Defence against open-redirect AND against stale/invalid stored app URLs
# dumping the user on a 404 right after successful login.)
_SAFE_REDIRECT_PREFIXES = ("/odoo/", "/odoo?", "/web/", "/web?", "/my/", "/my?")
_SAFE_REDIRECT_EXACT = frozenset({"/odoo", "/web", "/my"})
_FALLBACK_REDIRECT = "/odoo"
_DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7  # 7 days


def _allowed_parent_origins():
    raw = os.environ.get("ALLOWED_IFRAME_ORIGINS", "").strip()
    if not raw:
        return []
    return [o.strip().rstrip("/") for o in raw.split() if o.strip()]


def _request_matches_allowlist(http_request):
    """Verify the POST comes from an allow-listed builder origin.

    We check Origin first (set by browsers on cross-site POSTs) and fall back
    to Referer for edge cases. Keeps the route safe even with ``csrf=False``.
    """
    allowed = _allowed_parent_origins()
    if not allowed:
        return False
    origin = (http_request.headers.get("Origin") or "").strip().rstrip("/")
    if origin:
        return origin in allowed
    referer = (http_request.headers.get("Referer") or "").strip()
    if not referer:
        return False
    try:
        p = urlparse(referer)
        ref_origin = f"{p.scheme}://{p.netloc}".rstrip("/")
    except Exception:
        return False
    return ref_origin in allowed


def _safe_redirect_path(redirect_raw, odoo_root_url):
    """Normalise ``redirect_raw`` to a same-origin relative path.

    Returns the safe path, or :data:`_FALLBACK_REDIRECT` if the input is
    empty / protocol-relative / cross-origin / outside the known-safe prefix
    list. Never returns an absolute URL.

    Accepts::

        "/odoo/action-333"           → "/odoo/action-333"
        "https://same-host/odoo/x"   → "/odoo/x"
        "/odoo/action-333?k=v#frag"  → "/odoo/action-333?k=v" (fragment dropped)

    Rejects (→ fallback)::

        "", None, "   "              (empty)
        "//evil.example/x"           (protocol-relative, open-redirect vector)
        "https://evil.example/..."   (cross-origin)
        "/arbitrary/path"            (not a known-safe Odoo prefix)
    """
    if not redirect_raw or not redirect_raw.strip():
        return _FALLBACK_REDIRECT
    redirect_raw = redirect_raw.strip()

    # Protocol-relative URLs ("//host/...") are an open-redirect vector.
    if redirect_raw.startswith("//"):
        return _FALLBACK_REDIRECT

    if redirect_raw.startswith("/"):
        path_with_query = redirect_raw
    else:
        try:
            target = urlparse(redirect_raw)
            base = urlparse(odoo_root_url)
        except Exception:
            return _FALLBACK_REDIRECT
        if target.scheme not in ("http", "https") or not target.netloc:
            return _FALLBACK_REDIRECT
        if target.netloc != base.netloc:
            return _FALLBACK_REDIRECT
        path_with_query = target.path or "/"
        if target.query:
            path_with_query += "?" + target.query
        # Drop the fragment intentionally — it is never sent to the server
        # and cannot be meaningfully preserved through an HTTP redirect.

    # Strip any fragment that slipped through on a relative input.
    frag_idx = path_with_query.find("#")
    if frag_idx != -1:
        path_with_query = path_with_query[:frag_idx]

    # Validate against the allow-list of Odoo URL prefixes.
    if path_with_query in _SAFE_REDIRECT_EXACT:
        return path_with_query
    for pref in _SAFE_REDIRECT_PREFIXES:
        if path_with_query.startswith(pref):
            return path_with_query
    return _FALLBACK_REDIRECT


class VibeIframeAuth(http.Controller):
    @http.route(
        "/vibe_iframe/trusted_login",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        save_session=False,  # persistence is handled explicitly below
    )
    def trusted_login(self, **kw):
        """Authenticate with sandbox admin creds, then 303 → ``redirect``.

        POST form fields: ``db``, ``login``, ``password``, ``redirect``.

        On success: 303 to a safe Odoo path with ``Set-Cookie: session_id=...``
                    (httponly, on the Odoo origin).
        On failure: 400 / 401 / 403 plain-text response.
        """
        req = request.httprequest
        if not _request_matches_allowlist(req):
            _logger.warning(
                "iframe_allow: trusted_login blocked by origin allow-list "
                "(Origin=%r Referer=%r)",
                req.headers.get("Origin"),
                req.headers.get("Referer"),
            )
            return request.make_response("Forbidden", status=403)

        db = (request.params.get("db") or "").strip()
        login = (request.params.get("login") or "").strip()
        password = request.params.get("password") or ""
        redir_raw = (request.params.get("redirect") or "").strip()
        if not (db and login and password):
            return request.make_response("Bad Request", status=400)
        if db not in http.db_filter([db]):
            # Rejects databases outside the server's dbfilter — prevents
            # session-pinning to an unexpected db via a forged ``db`` param.
            _logger.warning(
                "iframe_allow: trusted_login db=%r rejected by db_filter", db
            )
            return request.make_response("Bad Request", status=400)

        odoo_root = req.url_root.rstrip("/")
        target_path = _safe_redirect_path(redir_raw, odoo_root)
        if target_path == _FALLBACK_REDIRECT and redir_raw:
            _logger.info(
                "iframe_allow: redirect=%r not in allow-list — falling back "
                "to %s",
                redir_raw,
                _FALLBACK_REDIRECT,
            )

        # Bind session to the requested db BEFORE authenticate so the cookie
        # we set below is tagged to the correct db. Mirrors ``ensure_db()``.
        if getattr(request.session, "db", None) != db:
            request.session = http.root.session_store.new()
            request.session.update(http.get_default_session(), db=db)
            request.session.context["lang"] = request.default_lang()

        credential = {
            "login": login,
            "password": password,
            "type": "password",
        }

        # Authenticate + persist + build the response **inside** the ExitStack
        # so the cursor/env stays alive while the session_store rotates (which
        # calls ``security.compute_session_token(session, env)`` on the env)
        # and while ``get_session_max_inactivity`` reads ir.config_parameter.
        try:
            with ExitStack() as stack:
                if not request.db or request.db != db:
                    cr = stack.enter_context(
                        odoo.modules.registry.Registry(db).cursor()
                    )
                    env = api.Environment(cr, odoo.SUPERUSER_ID, {})
                else:
                    env = request.env

                request.session.authenticate(env, credential)

                # After authenticate(), ``request.session.uid`` is set ONLY
                # when finalize() ran — i.e. 2FA was disabled or already
                # satisfied. For the auto-login flow we require a fully
                # finalized session; partial (pre_uid-only) sessions can't
                # auto-login a user without extra UI.
                uid = request.session.uid
                if not uid:
                    _logger.warning(
                        "iframe_allow: no finalized uid after authenticate "
                        "(MFA on %r in db=%r?)",
                        login,
                        db,
                    )
                    return request.make_response(
                        "Multi-factor authentication is required; "
                        "auto-login unsupported.",
                        status=401,
                    )

                # Persist session to disk with the right env. Rotation gives
                # a fresh sid and computes a new session_token bound to the
                # new sid — matching what /web/login would produce.
                try:
                    http.root.session_store.rotate(request.session, env)
                except Exception:
                    _logger.exception(
                        "iframe_allow: session_store.rotate failed; "
                        "falling back to save()"
                    )
                    http.root.session_store.save(request.session)

                try:
                    max_age = get_session_max_inactivity(env)
                except Exception:
                    max_age = _DEFAULT_SESSION_TTL_SECONDS

                _logger.info(
                    "iframe_allow: trusted_login OK uid=%s db=%s → %s",
                    uid,
                    db,
                    target_path,
                )

                # Build the response explicitly with werkzeug — no reliance
                # on request.redirect() / request.future_response. The cookie
                # attributes match Odoo's own session cookie
                # (see http.py::_save_session L2120): HttpOnly, SameSite=Lax,
                # ``Secure`` only when the request itself is secure so local
                # dev over http still works.
                response = werkzeug.utils.redirect(target_path, code=303)
                response.set_cookie(
                    "session_id",
                    request.session.sid,
                    max_age=max_age,
                    httponly=True,
                    secure=req.is_secure,
                    samesite="Lax",
                    path="/",
                )
                return response
        except AccessDenied:
            _logger.info(
                "iframe_allow: AccessDenied for login=%r db=%r", login, db
            )
            return request.make_response("Unauthorized", status=401)
        except Exception:
            _logger.exception(
                "iframe_allow: trusted_login failed for login=%r db=%r",
                login,
                db,
            )
            return request.make_response("Internal Server Error", status=500)
