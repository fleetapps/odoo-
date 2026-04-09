import logging
import os
import re
from datetime import timedelta

import psycopg2
from odoo import api, fields, models

_logger = logging.getLogger(__name__)

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5432')
DB_USER = os.environ.get('DB_USER', 'odoo')
DB_PASSWORD = os.environ.get('DB_PASSWORD', '')
TEMPLATE_DB = os.environ.get('TEMPLATE_DB', 'odin_template')


def _safe_db_name(name: str) -> bool:
    """Hard guard: only ever touch odoo_preview_* databases."""
    return bool(re.match(r'^odoo_preview_[a-zA-Z0-9_]{8,32}$', name or ''))


def _drop_database(db_name: str):
    if not _safe_db_name(db_name):
        raise ValueError(f'Safety guard: refusing to drop non-preview DB: {db_name}')

    conn = psycopg2.connect(
        host=DB_HOST, port=int(DB_PORT),
        user=DB_USER, password=DB_PASSWORD,
        dbname='postgres'
    )
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            # Terminate all connections to the DB before dropping
            cur.execute("""
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s AND pid <> pg_backend_pid()
            """, (db_name,))
            cur.execute(f'DROP DATABASE IF EXISTS "{db_name}"')
    finally:
        conn.close()


class OdinSession(models.Model):
    """
    Audit and orchestration record. Lives ONLY in odin_template.
    Session DBs (odoo_preview_*) contain a copy of this model from
    the clone but no records — records are never written there.
    """
    _name = 'odin.session'
    _description = 'ODIN Preview Session'
    _order = 'created_at desc'

    token = fields.Char(required=True, index=True, copy=False)
    token_used = fields.Boolean(default=False)
    token_expires_at = fields.Datetime()
    db_name = fields.Char(required=True, index=True)
    user_login = fields.Char()
    temp_password = fields.Char(copy=False)   # wiped after first autologin
    module_name = fields.Char()               # tracking only, not used for cleanup
    created_at = fields.Datetime(default=fields.Datetime.now, index=True)
    expires_at = fields.Datetime(index=True)

    @api.model
    def cleanup_stale_sessions(self):
        """
        Cron entry point. Only executes in odin_template.
        Drops entire session DBs — no module uninstall, no user deletion needed.
        """
        # Hard guard: cron copied to cloned DBs must not run there
        if self.env.cr.dbname != TEMPLATE_DB:
            _logger.info('ODIN cleanup: skipping — not in template DB (current: %s)', self.env.cr.dbname)
            return

        cutoff = fields.Datetime.now() - timedelta(hours=24)
        stale = self.search([('expires_at', '<', cutoff)])

        if not stale:
            _logger.info('ODIN cleanup: no stale sessions found')
            return

        _logger.info('ODIN cleanup: found %d stale session(s)', len(stale))

        for session in stale:
            db = session.db_name

            if not db or not _safe_db_name(db):
                _logger.error('ODIN cleanup: skipping unsafe db_name: %s', db)
                session.sudo().unlink()
                continue

            try:
                _drop_database(db)
                _logger.info('ODIN cleanup: dropped DB %s', db)
            except Exception as e:
                _logger.error('ODIN cleanup: failed to drop %s: %s', db, e)
                # Don't delete session record if drop failed — retry next cron run
                continue

            session.sudo().unlink()
            _logger.info('ODIN cleanup: removed session record for %s', db)