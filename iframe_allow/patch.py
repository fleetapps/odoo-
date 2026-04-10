import os

def apply_iframe_patch():
    from odoo.http import Response
    origins = os.environ.get('ALLOWED_IFRAME_ORIGINS', '')
    if not origins:
        return

    original_dispatch = Response.__call__

    def patched_dispatch(self, *args, **kwargs):
        response = original_dispatch(self, *args, **kwargs)
        try:
            response.headers.discard('X-Frame-Options')
            response.headers['Content-Security-Policy'] = f"frame-ancestors 'self' {origins}"
        except Exception:
            pass
        return response

    Response.__call__ = patched_dispatch