FROM nginx:1.27-alpine

# nginx prefix is /etc/nginx/, so `root html;` and `error_log logs/...` in the
# demo config resolve to /etc/nginx/html and /etc/nginx/logs. The stock image
# only ships /usr/share/nginx/html, so we create the relative-prefix targets.
RUN mkdir -p /etc/nginx/html /etc/nginx/logs \
 && printf '<!doctype html><html><body>cross-mode-it</body></html>\n' > /etc/nginx/html/index.html

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
