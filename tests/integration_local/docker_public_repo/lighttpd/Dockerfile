FROM alpine:3.21

ARG PUBLIC_REPO_URL=https://github.com/Armanyich/external-tests.git
ARG PUBLIC_REPO_REF=master
ARG PUBLIC_REPO_CACHE_KEY=

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

RUN echo "${PUBLIC_REPO_CACHE_KEY}" \
    && git init /opt/webconf-audit-src \
    && git -C /opt/webconf-audit-src remote add origin "${PUBLIC_REPO_URL}" \
    && git -C /opt/webconf-audit-src fetch --depth 1 origin "${PUBLIC_REPO_REF}" \
    && git -C /opt/webconf-audit-src checkout --detach FETCH_HEAD \
    && actual_commit="$(git -C /opt/webconf-audit-src rev-parse HEAD)" \
    && { test -z "${PUBLIC_REPO_CACHE_KEY}" || test "${actual_commit}" = "${PUBLIC_REPO_CACHE_KEY}"; } \
    && /opt/webconf-audit-venv/bin/pip install --upgrade pip \
    && /opt/webconf-audit-venv/bin/pip install /opt/webconf-audit-src

CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]
