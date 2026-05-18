FROM httpd:2.4-alpine

# mod_ssl is needed for the SSLEngine directives in the demo vhost. The stock
# alpine image keeps the LoadModule line commented; we enable it explicitly.
RUN { grep '^LoadModule' /usr/local/apache2/conf/httpd.conf; \
      echo 'LoadModule ssl_module modules/mod_ssl.so'; \
      echo 'LoadModule socache_shmcb_module modules/mod_socache_shmcb.so'; } \
    > /tmp/loadmodules.conf

# Self-signed certificate bound to the exact paths the demo references.
RUN apk add --no-cache openssl \
 && mkdir -p /usr/local/apache2/conf/ssl \
 && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /usr/local/apache2/conf/ssl/server.key \
        -out /usr/local/apache2/conf/ssl/server.crt \
        -days 30 \
        -subj "/CN=tls.example.test" \
        -addext "subjectAltName=DNS:tls.example.test,DNS:localhost,IP:127.0.0.1" \
 && chmod 600 /usr/local/apache2/conf/ssl/server.key \
 && apk del openssl

COPY httpd.conf /tmp/demo.conf
COPY htdocs/ /usr/local/apache2/htdocs/

# The demo config doesn't include SSLCertificate paths, so we append them. The
# certificate paths live entirely inside the container and never leak outside.
RUN cat /tmp/loadmodules.conf /tmp/demo.conf > /usr/local/apache2/conf/httpd.conf \
 && cat <<'EOF' >> /usr/local/apache2/conf/httpd.conf

# Build-time additions wiring the demo SSLEngine directives to the self-signed
# certificate generated above.
<IfModule ssl_module>
    SSLCertificateFile "/usr/local/apache2/conf/ssl/server.crt"
    SSLCertificateKeyFile "/usr/local/apache2/conf/ssl/server.key"
</IfModule>
EOF
RUN rm /tmp/loadmodules.conf /tmp/demo.conf

EXPOSE 443
