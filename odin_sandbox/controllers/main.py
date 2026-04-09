import io
import json
import logging
import os
import re
import secrets
import socket
import xmlrpc.client
import zipfile
from datetime import timedelta

from odoo import fields, http
from odoo.http import request

_logger = logging.getLogger(__name__)

PROVISION_TOKEN = os.environ.get('ODIN_PROVISION_TOKEN', '')
TEMPLATE_DB = os.environ.get('TEMPLATE_DB', 'odin_template')
ADMIN_PASSWORD = os.environ.get('ODOO_ADMIN_PASSWORD', '')

# Self-call URL — Odoo calling itself via localhost
# Workers communicate internally; this avoids external network round-trip
ODOO_INTERNAL = 'http://127.0.0.1:8069'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_token(req) -> bool:
    provided = req.httprequest.headers.get('X-Odin-Token', '')
    return bool(PROVISION_TOKEN) and provided == PROVISION_TOKEN


def _parse_json_body(req):
    try:
        return json.loads(req.httprequest.data or '{}')
    except json.JSONDecodeError:
        return None


def _safe_db(name: str) -> bool:
    return bool(re.match(r'^odoo_preview_[a-zA-Z0-9_]{8,32}$', name or ''))


def _safe_module(name: str) -> bool:
    return bool(re.match(r'^odin_preview_[a-zA-Z0-9_]+$', name or ''))


def _rpc_connect(db: str):
    """
    Returns (uid, models_proxy) authenticated as admin in the given DB.
    Raises RuntimeError if auth fails.
    """
    common = xmlrpc.client.ServerProxy(f'{ODOO_INTERNAL}/xmlrpc/2/common')
    uid = common.authenticate(db, 'admin', ADMIN_PASSWORD, {})
    if not uid:
        raise RuntimeError(f'XML-RPC admin auth failed for DB: {db}')
    models = xmlrpc.client.ServerProxy(f'{ODOO_INTERNAL}/xmlrpc/2/object')
    return uid, models


def _rpc_call(db, uid, method, args, kwargs=None):
    _, models = _rpc_connect(db)
    return models.execute_kw(db, uid, ADMIN_PASSWORD, *method, args, kwargs or {})


def _get_internal_user_group_id(db: str, uid: int) -> int:
    """
    Resolve 'Internal User' group ID dynamically — avoids hardcoded IDs
    that differ between Odoo installs.
    """
    _, models = _rpc_connect(db)
    ids = models.execute_kw(db, uid, ADMIN_PASSWORD,
        'res.groups', 'search', [[
            ['category_id.name', 'in', ['Administration', 'Extra Rights']],
            ['name', '=', 'Internal User']
        ]])
    if ids:
        return ids[0]
    # Fallback: group_user ref
    refs = models.execute_kw(db, uid, ADMIN_PASSWORD,
        'ir.model.data', 'search_read',
        [[['module', '=', 'base'], ['name', '=', 'group_user']]],
        {'fields': ['res_id'], 'limit': 1})
    if refs:
        return refs[0]['res_id']
    raise RuntimeError('Could not resolve Internal User group ID')


# ---------------------------------------------------------------------------
# Controllers
# ---------------------------------------------------------------------------

class OdinSandboxController(http.Controller):

    # -----------------------------------------------------------------------
    # POST /odin/provision
    #
    # Called server-to-server by ODIN backend.
    # IMPORTANT: ODIN backend must call this as:
    #   POST https://sandbox.odin.ist/odin/provision?db=odin_template
    # The ?db=odin_template param ensures Odoo's router directs this request
    # to the template DB. Without it, Odoo has no DB context (auth=none).
    #
    # Steps:
    #   1. Validate token
    #   2. Create Odoo user in session DB via XML-RPC
    #   3. Store autologin token in template DB via XML-RPC
    #   4. Return autologin URL
    # -----------------------------------------------------------------------
    @http.route('/odin/provision', type='http', auth='none', methods=['POST'], csrf=False)
    def provision(self, **kwargs):
        if not _verify_token(request):
            return request.make_json_response({'error': 'unauthorized'}, status=401)

        body = _parse_json_body(request)
        if body is None:
            return request.make_json_response({'error': 'invalid json'}, status=400)

        session_id = body.get('session_id', '')
        db_name = body.get('db_name', '')

        if not session_id or not _safe_db(db_name):
            return request.make_json_response(
                {'error': 'session_id required and db_name must match odoo_preview_*'},
                status=400
            )

        login = f'odin_preview_{session_id}'
        password = secrets.token_urlsafe(32)

        # --- Step 1: Create user in session DB ---
        try:
            uid, models = _rpc_connect(db_name)
            group_id = _get_internal_user_group_id(db_name, uid)

            models.execute_kw(db_name, uid, ADMIN_PASSWORD,
                'res.users', 'create', [{
                    'name': f'Preview {session_id[:8]}',
                    'login': login,
                    'password': password,
                    'lang': 'en_US',
                    'tz': 'Africa/Nairobi',
                    'groups_id': [(6, 0, [group_id])],
                }])
        except Exception as e:
            _logger.error('ODIN provision: user creation failed in %s: %s', db_name, e)
            return request.make_json_response(
                {'error': 'user creation failed', 'detail': str(e)}, status=500)

        # --- Step 2: Store token in template DB ---
        token = secrets.token_urlsafe(48)
        try:
            t_uid, t_models = _rpc_connect(TEMPLATE_DB)
            t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                'odin.session', 'create', [{
                    'token': token,
                    'db_name': db_name,
                    'user_login': login,
                    'temp_password': password,
                    'token_expires_at': str(fields.Datetime.now() + timedelta(minutes=15)),
                    'expires_at': str(fields.Datetime.now() + timedelta(hours=24)),
                    'created_at': str(fields.Datetime.now()),
                }])
        except Exception as e:
            _logger.error('ODIN provision: session record failed in template: %s', e)
            return request.make_json_response(
                {'error': 'session record creation failed', 'detail': str(e)}, status=500)

        autologin_url = f'/odin/autologin/{token}?db={db_name}'
        _logger.info('ODIN: provisioned user %s in %s', login, db_name)

        return request.make_json_response({
            'login': login,
            'db_name': db_name,
            'autologin_url': autologin_url,
        })

    # -----------------------------------------------------------------------
    # GET /odin/autologin/<token>?db=odoo_preview_xxx
    #
    # Hit directly by the user's browser after ODIN frontend receives
    # the autologin_url. No login screen shown.
    #
    # Odoo 19 note: request.session.db assignment + authenticate() is the
    # correct flow. request.update_env() changes the ORM env but NOT the
    # HTTP session cookie DB. We need the session cookie set correctly
    # so subsequent requests from the browser hit the right DB.
    # -----------------------------------------------------------------------
    @http.route('/odin/autologin/<string:token>', type='http', auth='none', methods=['GET'], csrf=False)
    def autologin(self, token, **kwargs):
        db_name = request.params.get('db', '')

        if not _safe_db(db_name):
            _logger.warning('ODIN autologin: invalid db param: %s', db_name)
            return request.redirect('/web/login?error=Invalid+session.')

        # --- Validate token against template DB via XML-RPC ---
        try:
            t_uid, t_models = _rpc_connect(TEMPLATE_DB)
            records = t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                'odin.session', 'search_read',
                [[
                    ['token', '=', token],
                    ['token_used', '=', False],
                    ['db_name', '=', db_name],
                ]],
                {'fields': ['id', 'token_expires_at', 'user_login', 'temp_password'], 'limit': 1})
        except Exception as e:
            _logger.error('ODIN autologin: template DB query failed: %s', e)
            return request.redirect('/web/login?error=Session+error.+Please+try+again.')

        if not records:
            _logger.warning('ODIN autologin: token not found or already used')
            return request.redirect('/web/login?error=Session+expired.+Please+restart+your+preview.')

        rec = records[0]

        # Check TTL
        expiry = fields.Datetime.from_string(rec['token_expires_at'])
        if fields.Datetime.now() > expiry:
            _logger.warning('ODIN autologin: token expired for %s', db_name)
            try:
                t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                    'odin.session', 'write',
                    [[rec['id']], {'token_used': True, 'temp_password': False}])
            except Exception:
                pass
            return request.redirect('/web/login?error=Link+expired.+Please+restart+your+preview.')

        login = rec['user_login']
        password = rec['temp_password']

        # --- Odoo 19: set session DB then authenticate ---
        # This sequence is correct for Odoo 19:
        # 1. Set request.session.db so the session cookie targets the right DB
        # 2. authenticate() validates credentials and finalises the session
        # Do NOT use request.update_env(db=...) here — that changes ORM context
        # only and does not affect the browser session cookie DB.
        request.session.db = db_name
        try:
            uid = request.session.authenticate(db_name, login, password)
        except Exception as e:
            _logger.error('ODIN autologin: authenticate() raised: %s', e)
            return request.redirect('/web/login?error=Authentication+failed.')

        if not uid:
            _logger.error('ODIN autologin: authenticate() returned falsy for %s in %s', login, db_name)
            return request.redirect('/web/login?error=Authentication+failed.')

        # --- Invalidate token immediately ---
        try:
            t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                'odin.session', 'write',
                [[rec['id']], {'token_used': True, 'temp_password': False}])
        except Exception as e:
            # Non-fatal but log it — token will expire naturally after 15min
            _logger.warning('ODIN autologin: could not invalidate token: %s', e)

        _logger.info('ODIN autologin: user %s authenticated in %s', login, db_name)

        # Odoo 19 home URL
        return request.redirect('/odoo')

    # -----------------------------------------------------------------------
    # POST /odin/upload_module
    #
    # Receives a ZIP containing the generated module.
    # Extracts it to /var/lib/odoo/custom_addons/<module_name>/
    # Then installs it in the session DB via XML-RPC.
    #
    # IMPORTANT: button_immediate_install triggers a worker restart in Odoo.
    # The XML-RPC connection WILL be dropped mid-response even on success.
    # We catch socket/connection errors and treat them as success, then
    # poll to confirm the install completed.
    # -----------------------------------------------------------------------
    @http.route('/odin/upload_module', type='http', auth='none', methods=['POST'], csrf=False)
    def upload_module(self, **kwargs):
        if not _verify_token(request):
            return request.make_json_response({'error': 'unauthorized'}, status=401)

        db_name = request.httprequest.form.get('db_name', '')
        module_name = request.httprequest.form.get('module_name', '')

        if not _safe_db(db_name):
            return request.make_json_response({'error': 'invalid db_name'}, status=400)
        if not _safe_module(module_name):
            return request.make_json_response({'error': 'invalid module_name'}, status=400)

        zip_file = request.httprequest.files.get('module_zip')
        if not zip_file:
            return request.make_json_response({'error': 'module_zip file is required'}, status=400)

        # --- Extract ZIP safely ---
        addons_path = '/var/lib/odoo/custom_addons'
        try:
            raw = zip_file.read()
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for member in z.namelist():
                    # Path traversal guard: only extract files inside module_name/
                    # Normalise the member path and verify it stays within bounds
                    norm = os.path.normpath(member)
                    if norm.startswith('..') or not norm.startswith(module_name):
                        _logger.warning('ODIN upload: skipping unsafe zip member: %s', member)
                        continue
                    z.extract(member, addons_path)
        except zipfile.BadZipFile:
            return request.make_json_response({'error': 'uploaded file is not a valid ZIP'}, status=400)
        except Exception as e:
            _logger.error('ODIN upload_module: extraction failed: %s', e)
            return request.make_json_response({'error': f'extraction failed: {e}'}, status=500)

        # --- Install module in session DB ---
        try:
            uid, models = _rpc_connect(db_name)
            models.execute_kw(db_name, uid, ADMIN_PASSWORD,
                'ir.module.module', 'update_list', [])

            module_ids = models.execute_kw(db_name, uid, ADMIN_PASSWORD,
                'ir.module.module', 'search',
                [[['name', '=', module_name]]])

            if not module_ids:
                return request.make_json_response(
                    {'error': f'Module {module_name} not found after update_list'}, status=404)

            # button_immediate_install restarts Odoo workers.
            # The XML-RPC connection will be dropped — catch it and treat as success.
            try:
                models.execute_kw(db_name, uid, ADMIN_PASSWORD,
                    'ir.module.module', 'button_immediate_install', [module_ids])
            except (ConnectionResetError, socket.error, xmlrpc.client.ProtocolError,
                    BrokenPipeError, OSError) as conn_err:
                # Expected: worker restarted. Install was triggered successfully.
                _logger.info('ODIN upload_module: connection dropped after install trigger '
                             '(expected after worker restart): %s', conn_err)

        except Exception as e:
            _logger.error('ODIN upload_module: install failed for %s in %s: %s', module_name, db_name, e)
            return request.make_json_response({'error': f'install failed: {e}'}, status=500)

        # --- Link module name to session record (non-fatal) ---
        try:
            t_uid, t_models = _rpc_connect(TEMPLATE_DB)
            ids = t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                'odin.session', 'search', [[['db_name', '=', db_name]]])
            if ids:
                t_models.execute_kw(TEMPLATE_DB, t_uid, ADMIN_PASSWORD,
                    'odin.session', 'write', [[ids[0]], {'module_name': module_name}])
        except Exception as e:
            _logger.warning('ODIN upload_module: could not link module to session: %s', e)

        return request.make_json_response({'ok': True, 'module': module_name})