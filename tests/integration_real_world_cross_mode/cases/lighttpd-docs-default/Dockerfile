FROM alpine:3.20

RUN apk add --no-cache lighttpd \
 && mkdir -p /opt/lighttpd/www/htdocs /opt/lighttpd/logs /opt/lighttpd/conf.d

WORKDIR /opt/lighttpd

COPY lighttpd.conf /opt/lighttpd/lighttpd.conf
COPY conf.d/ /opt/lighttpd/conf.d/
COPY www/ /opt/lighttpd/www/

# Append debug logging so any request error surfaces in /opt/lighttpd/logs/error.log
RUN printf '\ndebug.log-request-handling = "enable"\ndebug.log-file-not-found = "enable"\n' >> /opt/lighttpd/lighttpd.conf

EXPOSE 8080

CMD ["lighttpd", "-D", "-f", "/opt/lighttpd/lighttpd.conf"]
