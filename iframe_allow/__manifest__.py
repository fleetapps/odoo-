{
    'name': 'Allow iFrame Embedding',
    'version': '1.0',
    'author': 'ODIN',
    'license': 'LGPL-3',
    'depends': ['web'],
    'installable': True,
    'post_load': 'apply_iframe_patch',
}
