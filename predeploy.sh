#!/bin/bash
set -e
cp -r /odoo_modules/odin_sandbox/. /var/lib/odoo/custom_addons/odin_sandbox/
cp -r /odoo_modules/iframe_allow/. /var/lib/odoo/custom_addons/iframe_allow/
odoo -d odin_template -i base,odin_sandbox,iframe_allow --stop-after-init
