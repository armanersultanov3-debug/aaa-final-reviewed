FROM alpine:3.20

RUN apk add --no-cache lighttpd openssl \
 && mkdir -p /opt/lighttpd/www/app /opt/lighttpd/logs /opt/lighttpd/certs

WORKDIR /opt/lighttpd

# Self-signed certificate in lighttpd "pemfile" format (cert + key in one PEM)
# bound to the path the demo config references so the config stays unmodified
# at the TLS-specific directives.
RUN openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /opt/lighttpd/certs/example.key \
        -out /opt/lighttpd/certs/example.crt \
        -days 30 \
        -subj "/CN=tls.example.test" \
        -addext "subjectAltName=DNS:tls.example.test,DNS:localhost,IP:127.0.0.1" \
 && cat /opt/lighttpd/certs/example.crt /opt/lighttpd/certs/example.key > /opt/lighttpd/certs/example.pem \
 && chmod 600 /opt/lighttpd/certs/example.pem

COPY lighttpd.conf /opt/lighttpd/lighttpd.conf
COPY www/ /opt/lighttpd/www/

EXPOSE 8443

CMD ["lighttpd", "-D", "-f", "/opt/lighttpd/lighttpd.conf"]
