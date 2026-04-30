FROM nginx:1.27

ARG PUBLIC_REPO_URL=https://github.com/armanersultanov8-cmd/aaa-final-reviewed.git

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/webconf-audit-venv

ENV PATH="/opt/webconf-audit-venv/bin:${PATH}"

RUN git clone --depth 1 --branch master "${PUBLIC_REPO_URL}" /opt/webconf-audit-src \
    && /opt/webconf-audit-venv/bin/pip install --upgrade pip \
    && /opt/webconf-audit-venv/bin/pip install /opt/webconf-audit-src
