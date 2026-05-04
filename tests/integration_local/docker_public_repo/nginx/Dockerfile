FROM nginx:1.27

ARG PUBLIC_REPO_URL=https://github.com/Armanyich/external-tests.git
ARG PUBLIC_REPO_REF=master
ARG PUBLIC_REPO_CACHE_KEY=

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        python3 \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/webconf-audit-venv

ENV PATH="/opt/webconf-audit-venv/bin:${PATH}"

RUN echo "${PUBLIC_REPO_CACHE_KEY}" \
    && git init /opt/webconf-audit-src \
    && git -C /opt/webconf-audit-src remote add origin "${PUBLIC_REPO_URL}" \
    && git -C /opt/webconf-audit-src fetch --depth 1 origin "${PUBLIC_REPO_REF}" \
    && git -C /opt/webconf-audit-src checkout --detach FETCH_HEAD \
    && actual_commit="$(git -C /opt/webconf-audit-src rev-parse HEAD)" \
    && test -z "${PUBLIC_REPO_CACHE_KEY}" || test "${actual_commit}" = "${PUBLIC_REPO_CACHE_KEY}" \
    && /opt/webconf-audit-venv/bin/pip install --upgrade pip \
    && /opt/webconf-audit-venv/bin/pip install /opt/webconf-audit-src
