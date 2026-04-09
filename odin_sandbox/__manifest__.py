{
    'name': 'ODIN Sandbox',
    'version': '2.0',
    'summary': 'Autologin, session provisioning and cleanup for ODIN ephemeral previews',
    'depends': ['base', 'web'],
    'data': [
        'security/ir.model.access.csv',
        'data/ir_cron.xml',
    ],
    'installable': True,
    'license': 'LGPL-3',
}