FROM httpd:2.4-alpine

# Extract LoadModule lines from the stock conf so the demo snippet doesn't
# need to redeclare them. mod_rewrite and mod_headers are required by the
# bundled .htaccess; both ship commented out in the alpine image, so we
# enable them explicitly.
RUN { grep '^LoadModule' /usr/local/apache2/conf/httpd.conf; \
      echo 'LoadModule rewrite_module modules/mod_rewrite.so'; \
      echo 'LoadModule headers_module modules/mod_headers.so'; } \
    > /tmp/loadmodules.conf

COPY httpd.conf /tmp/demo.conf
COPY conf.d/ /usr/local/apache2/conf.d/
COPY sites/ /usr/local/apache2/sites/

RUN cat /tmp/loadmodules.conf /tmp/demo.conf > /usr/local/apache2/conf/httpd.conf \
 && rm /tmp/loadmodules.conf /tmp/demo.conf

EXPOSE 80
