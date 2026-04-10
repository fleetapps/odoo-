FROM odoo:19.0
ENV ODOO_RC /etc/odoo/odoo.conf
COPY ./odoo.conf /etc/odoo/odoo.conf
COPY odin_sandbox/ /odoo_modules/odin_sandbox/
COPY iframe_allow/ /odoo_modules/iframe_allow/
COPY predeploy.sh /predeploy.sh
RUN chmod +x /predeploy.sh
