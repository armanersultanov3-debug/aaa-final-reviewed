FROM alpine:3.21

ARG PUBLIC_REPO_URL=https://github.com/armanersultanov8-cmd/aaa-final-reviewed.git

RUN apk add --no-cache \
        ca-certificates \
        git \
        lighttpd \
        openssl \
        py3-pip \
        python3

RUN mkdir -p /var/www/localhost/htdocs /var/log/lighttpd /var/lib/lighttpd \
    && printf '<html><body>lighttpd demo</body></html>\n' > /var/www/localhost/htdocs/index.html \
    && openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout /var/lib/lighttpd/demo.pem \
        -out /var/lib/lighttpd/demo.pem \
        -days 365 \
        -subj "/CN=demo.local"

RUN python3 -m venv /opt/webconf-audit-venv

ENV PATH="/opt/webconf-audit-venv/bin:${PATH}"

RUN git clone --depth 1 --branch master "${PUBLIC_REPO_URL}" /opt/webconf-audit-src \
    && /opt/webconf-audit-venv/bin/pip install --upgrade pip \
    && /opt/webconf-audit-venv/bin/pip install /opt/webconf-audit-src

CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
