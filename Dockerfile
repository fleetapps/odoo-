FROM odoo:19.0

# Use the official config path
ENV ODOO_RC /etc/odoo/odoo.conf

# Minimal setup: copy a basic config
COPY ./odoo.conf /etc/odoo/odoo.conf
