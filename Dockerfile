FROM odoo:19.0
# Use the official config path
ENV ODOO_RC /etc/odoo/odoo.conf
# Minimal setup: copy a basic config
COPY ./odoo.conf /etc/odoo/odoo.conf
COPY odin_sandbox/ /var/lib/odoo/custom_addons/odin_sandbox/
COPY iframe_allow/ /var/lib/odoo/custom_addons/iframe_allow/
