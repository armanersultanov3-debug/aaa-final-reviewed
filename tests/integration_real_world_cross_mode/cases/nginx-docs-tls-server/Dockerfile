FROM nginx:1.27-alpine

# nginx prefix is /etc/nginx/; the config uses relative `root html;` and
# relative `error_log logs/...` so we materialize both directories.
RUN mkdir -p /etc/nginx/html /etc/nginx/logs /etc/ssl/example \
 && printf '<!doctype html><html><body>tls-cross-mode</body></html>\n' > /etc/nginx/html/index.html

# Self-signed certificate generated at build time. We bind to the exact paths
# the public config references so the config stays unmodified.
RUN apk add --no-cache openssl \
 && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/ssl/example/privkey.pem \
        -out /etc/ssl/example/fullchain.pem \
        -days 30 \
        -subj "/CN=tls.example.test" \
        -addext "subjectAltName=DNS:tls.example.test,DNS:localhost,IP:127.0.0.1" \
 && chmod 600 /etc/ssl/example/privkey.pem \
 && apk del openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
