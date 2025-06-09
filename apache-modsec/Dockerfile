FROM ubuntu:22.04

# Install Apache and ModSecurity
RUN apt-get update && \
    apt-get install -y apache2 libapache2-mod-security2 && \
    a2enmod proxy proxy_http security2 && \
    mkdir -p /etc/modsecurity/rules && \
    mkdir -p /usr/share/modsecurity-crs/rules

# Copy Apache and ModSecurity configuration
COPY apache-config/ports.conf /etc/apache2/
COPY apache-config/myapp.conf /etc/apache2/sites-available/
COPY apache-config/modsecurity.conf /etc/modsecurity/

# Copy your custom rule file
COPY /custom-rules/custom_rules2.conf /usr/share/modsecurity-crs/rules/

# Enable site and add custom rule include if not already present
RUN mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf && \
    a2ensite myapp && \
    echo "SecRuleEngine On" >> /etc/modsecurity/modsecurity.conf 
    

EXPOSE 8880
CMD ["apache2ctl", "-D", "FOREGROUND"]
