FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-security2 && \
    a2enmod proxy proxy_http security2 && \
    mkdir -p /etc/modsecurity/rules

COPY apache-config/ports.conf /etc/apache2/
COPY apache-config/myapp.conf /etc/apache2/sites-available/
COPY apache-config/modsecurity.conf /etc/modsecurity/

RUN mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf && \
    a2ensite myapp && \
    echo "SecRuleEngine On" >> /etc/modsecurity/modsecurity.conf && \
    touch /etc/modsecurity/rules/default.conf

EXPOSE 8880
CMD ["apache2ctl", "-D", "FOREGROUND"]