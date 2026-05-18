FROM nginx:1.27-alpine

RUN mkdir -p /etc/nginx/html /etc/nginx/logs /etc/ssl/mozilla \
 && printf '<!doctype html><html><body>mozilla-old</body></html>\n' > /etc/nginx/html/index.html

RUN apk add --no-cache openssl \
 && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /etc/ssl/mozilla/privkey.pem \
        -out /etc/ssl/mozilla/fullchain.pem \
        -days 30 \
        -subj "/CN=old.example.test" \
        -addext "subjectAltName=DNS:old.example.test,DNS:localhost,IP:127.0.0.1" \
 && chmod 600 /etc/ssl/mozilla/privkey.pem \
 && apk del openssl

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
