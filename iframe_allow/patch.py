import os

def apply_iframe_patch():
    from odoo.http import Response, Root

    origins = os.environ.get('ALLOWED_IFRAME_ORIGINS', '')
    if not origins:
        return

    # --- EXISTING PATCH (slightly safer version) ---
    original_dispatch = Response.__call__

    def patched_dispatch(self, *args, **kwargs):
        response = original_dispatch(self, *args, **kwargs)
        try:
            # Remove frame blocking
            response.headers.pop('X-Frame-Options', None)

            # Safer CSP merge (don’t nuke everything)
            existing = response.headers.get('Content-Security-Policy', '')
            response.headers['Content-Security-Policy'] = (
                f"{existing}; frame-ancestors 'self' {origins}"
            )
        except Exception:
            pass
        return response

    Response.__call__ = patched_dispatch

    original_set_cookie = Root.set_cookie

    def patched_set_cookie(self, response, key, value='', **kwargs):
        if key == 'session_id':
            kwargs['samesite'] = 'None'
            kwargs['secure'] = True

        return original_set_cookie(self, response, key, value, **kwargs)

    Root.set_cookie = patched_set_cookie
