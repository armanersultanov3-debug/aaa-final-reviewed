FROM httpd:2.4

ARG PUBLIC_REPO_URL=https://github.com/armanersultanov8-cmd/aaa-final-reviewed.git
ARG PUBLIC_REPO_REF=master

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/webconf-audit-venv

ENV PATH="/opt/webconf-audit-venv/bin:${PATH}"

RUN git init /opt/webconf-audit-src \
    && git -C /opt/webconf-audit-src remote add origin "${PUBLIC_REPO_URL}" \
    && git -C /opt/webconf-audit-src fetch --depth 1 origin "${PUBLIC_REPO_REF}" \
    && git -C /opt/webconf-audit-src checkout --detach FETCH_HEAD \
    && /opt/webconf-audit-venv/bin/pip install --upgrade pip \
    && /opt/webconf-audit-venv/bin/pip install /opt/webconf-audit-src
