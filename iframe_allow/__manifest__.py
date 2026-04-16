{
    'name': 'Allow iFrame Embedding',
    'version': '1.2.0',
    'summary': 'Trusted auto-login + iframe-embedding headers for the vibe-odoo builder',
    'author': 'Odin',
    'category': 'Technical',
    'author': 'ODIN',
    'license': 'LGPL-3',
    'depends': ['web'],
    'installable': True,
    'post_load': 'apply_iframe_patch',
    'auto_install': True,
    'application': False,
}
