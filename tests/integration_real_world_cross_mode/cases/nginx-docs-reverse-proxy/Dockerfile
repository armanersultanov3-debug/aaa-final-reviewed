FROM nginx:1.27-alpine

RUN mkdir -p /etc/nginx/logs

COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/ /etc/nginx/conf.d/
