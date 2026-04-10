{
    'name': 'Allow iFrame Embedding',
    'version': '1.0',
    'depends': ['web'],
    'installable': True,
    'post_load': 'apply_iframe_patch',
}